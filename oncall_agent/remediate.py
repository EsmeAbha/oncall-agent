"""Automated remediation, with every limit an SRE would want before trusting it.

An action runs automatically only if ALL of these hold; otherwise it becomes a
suggestion with the exact command, and a human decides:

- auto-remediation is switched on (kill switch: AUTO_REMEDIATE=false)
- the action is on the allowlist and the namespace is allowlisted
- the diagnosis is high-confidence with nothing arguing against it
- no automatic action touched this deployment within the cooldown
- the global budget of automatic actions per hour isn't spent
- this replica holds the remediation lease (only one actor, even with several replicas)

Rollback does what `kubectl rollout undo` does: copy the previous ReplicaSet's
pod template back onto the deployment.
"""
from __future__ import annotations

import copy
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .diagnose import Diagnosis
from .sources import REVISION, Kube


@dataclass
class Policy:
    auto_enabled: bool = False
    namespaces: frozenset[str] = frozenset()
    actions: frozenset[str] = frozenset({"rollback", "scale_up"})
    cooldown_s: float = 1800
    max_auto_per_hour: int = 3
    max_replicas: int = 10


@dataclass
class Plan:
    action: str | None
    namespace: str
    deployment: str
    command: str
    auto: bool
    blocked_by: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)


class Lock(Protocol):
    def acquire(self) -> bool: ...


class LocalLock:
    def __init__(self, held: bool = True):
        self.held = held

    def acquire(self) -> bool:
        return self.held


class LeaseLock:
    """Leader election on a coordination.k8s.io Lease, using optimistic concurrency.

    Every write carries the resourceVersion we read. If another replica wrote in
    between, the API server answers 409 and we have simply lost; nobody can
    acquire a lease someone else holds and is still renewing.
    """

    def __init__(self, kube: Kube, namespace: str, name: str, holder: str, ttl_s: int = 30,
                 now=lambda: datetime.now(timezone.utc)):
        self.kube, self.ns, self.name, self.holder, self.ttl, self.now = kube, namespace, name, holder, ttl_s, now
        self.path = f"/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases"

    def _spec(self) -> dict[str, Any]:
        stamp = self.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return {"holderIdentity": self.holder, "leaseDurationSeconds": self.ttl,
                "acquireTime": stamp, "renewTime": stamp}

    def acquire(self) -> bool:
        r = self.kube.request("GET", f"{self.path}/{self.name}")
        if r.status_code == 404:
            body = {"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
                    "metadata": {"name": self.name, "namespace": self.ns}, "spec": self._spec()}
            return self.kube.request("POST", self.path, body).status_code == 201
        r.raise_for_status()
        lease = r.json()
        spec = lease.get("spec", {})
        if spec.get("holderIdentity") not in (None, "", self.holder):
            renewed = datetime.fromisoformat(spec["renewTime"].replace("Z", "+00:00"))
            if self.now() < renewed + timedelta(seconds=spec.get("leaseDurationSeconds", self.ttl)):
                return False                      # someone else holds a live lease
        lease["spec"] = self._spec()              # metadata.resourceVersion stays: that's the CAS
        return self.kube.request("PUT", f"{self.path}/{self.name}", lease).status_code == 200


class Remediator:
    def __init__(self, kube: Kube | None, policy: Policy, lock: Lock, clock=time.time):
        self.kube, self.policy, self.lock, self.clock = kube, policy, lock, clock
        self.history: list[tuple[float, str]] = []   # (time, "ns/deployment") of automatic actions

    def plan(self, diagnosis: Diagnosis, svc: dict) -> Plan:
        ns, dep = svc["namespace"], svc["deployment"]
        top = diagnosis.top
        if top is None or top.action is None:
            return Plan(None, ns, dep, "", False, ["no safe automatic action for this diagnosis"])
        p = self.policy
        params: dict[str, Any] = {}
        if top.action == "rollback":
            cmd = f"kubectl -n {ns} rollout undo deployment/{dep}"
        else:
            rollout = diagnosis.evidence.get("rollout")
            current = ((rollout.value if rollout else None) or {}).get("replicas") or svc.get("replicas", 2)
            params["replicas"] = min(math.ceil(current * 1.5), p.max_replicas)
            if params["replicas"] <= current:
                return Plan(top.action, ns, dep, "", False, [f"already at max_replicas={p.max_replicas}"])
            cmd = f"kubectl -n {ns} scale deployment/{dep} --replicas={params['replicas']}"

        blocked = []
        now = self.clock()
        if not p.auto_enabled:
            blocked.append("auto-remediation is switched off")
        if top.action not in p.actions:
            blocked.append(f"{top.action} is not on the allowlist")
        if ns not in p.namespaces:
            blocked.append(f"namespace {ns} is not allowlisted")
        if top.confidence != "high":
            blocked.append(f"confidence is {top.confidence}, auto needs high")
        if diagnosis.missing:
            blocked.append(f"evidence missing ({', '.join(diagnosis.missing)}), so the picture may be incomplete")
        if any(t > now - p.cooldown_s and target == f"{ns}/{dep}" for t, target in self.history):
            blocked.append(f"an automatic action already ran on {dep} in the last {p.cooldown_s / 60:.0f} min")
        if sum(t > now - 3600 for t, _ in self.history) >= p.max_auto_per_hour:
            blocked.append(f"hourly budget of {p.max_auto_per_hour} automatic actions is spent")
        return Plan(top.action, ns, dep, cmd, not blocked, blocked, params)

    def execute(self, plan: Plan) -> dict[str, Any]:
        if not plan.auto or plan.action is None:
            return {"executed": False, "suggested_command": plan.command, "why_not_automatic": plan.blocked_by}
        if not self.lock.acquire():
            return {"executed": False, "suggested_command": plan.command,
                    "why_not_automatic": ["another replica holds the remediation lease"]}
        self.history.append((self.clock(), f"{plan.namespace}/{plan.deployment}"))
        if plan.action == "rollback":
            detail = rollback(self.kube, plan.namespace, plan.deployment)
        else:
            self.kube.patch(f"/apis/apps/v1/namespaces/{plan.namespace}/deployments/{plan.deployment}/scale",
                            {"spec": {"replicas": plan.params["replicas"]}}, "application/merge-patch+json")
            detail = {"replicas": plan.params["replicas"]}
        return {"executed": True, "action": plan.action, "command_equivalent": plan.command, **detail}


def rollback(kube: Kube, ns: str, deployment: str) -> dict[str, Any]:
    """`kubectl rollout undo`: put the previous revision's pod template back."""
    rss = kube.replicasets(ns, deployment)
    if len(rss) < 2:
        raise RuntimeError("no previous revision to roll back to")
    current, previous = rss[0], rss[1]
    template = copy.deepcopy(previous["spec"]["template"])
    template["metadata"].get("labels", {}).pop("pod-template-hash", None)
    kube.patch(f"/apis/apps/v1/namespaces/{ns}/deployments/{deployment}",
               [{"op": "replace", "path": "/spec/template", "value": template}], "application/json-patch+json")
    return {"from_revision": int(current["metadata"]["annotations"][REVISION]),
            "to_revision": int(previous["metadata"]["annotations"][REVISION]),
            "to_image": template["spec"]["containers"][0]["image"]}
