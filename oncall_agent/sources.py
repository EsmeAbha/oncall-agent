"""Where evidence comes from: Prometheus and the Kubernetes API.

Both clients are thin HTTP wrappers (no SDKs), so what each call does is easy
to see and to fake in tests. `LiveSources` turns raw API answers into the
facts the playbooks reason about. Every fact can fail independently; the
collector records the failure and diagnosis carries on with what it has.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Protocol

import httpx

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
REVISION = "deployment.kubernetes.io/revision"


class SourceError(Exception):
    pass


class Prometheus:
    def __init__(self, url: str, client: httpx.Client | None = None):
        self._url = url.rstrip("/")
        self._client = client or httpx.Client(timeout=5)

    def query(self, promql: str) -> list[dict[str, Any]]:
        r = self._client.get(f"{self._url}/api/v1/query", params={"query": promql})
        r.raise_for_status()
        body = r.json()
        if body.get("status") != "success":
            raise SourceError(body.get("error", "query failed"))
        return [{"labels": s["metric"], "value": float(s["value"][1])} for s in body["data"]["result"]]

    def scalar(self, promql: str) -> float | None:
        rows = self.query(promql)
        return rows[0]["value"] if rows else None


class Kube:
    """Minimal Kubernetes REST client. In a pod it uses the mounted service-account token."""

    def __init__(self, base_url: str | None = None, token: str | None = None, client: httpx.Client | None = None):
        if client is None:
            host = os.environ.get("KUBERNETES_SERVICE_HOST")
            base_url = base_url or f"https://{host}:{os.environ.get('KUBERNETES_SERVICE_PORT', '443')}"
            token = token or open(f"{SA_DIR}/token").read()
            client = httpx.Client(base_url=base_url, timeout=5, verify=f"{SA_DIR}/ca.crt",
                                  headers={"Authorization": f"Bearer {token}"})
        self._c = client

    def _get(self, path: str, **params) -> dict[str, Any]:
        r = self._c.get(path, params=params or None)
        r.raise_for_status()
        return r.json()

    def deployment(self, ns: str, name: str) -> dict[str, Any]:
        return self._get(f"/apis/apps/v1/namespaces/{ns}/deployments/{name}")

    def replicasets(self, ns: str, deployment: str) -> list[dict[str, Any]]:
        """ReplicaSets owned by the deployment, newest revision first."""
        items = self._get(f"/apis/apps/v1/namespaces/{ns}/replicasets")["items"]
        owned = [rs for rs in items if any(o.get("kind") == "Deployment" and o.get("name") == deployment
                                           for o in rs["metadata"].get("ownerReferences", []))]
        return sorted(owned, key=lambda rs: int(rs["metadata"].get("annotations", {}).get(REVISION, 0)),
                      reverse=True)

    def warning_events(self, ns: str, prefix: str) -> list[dict[str, Any]]:
        items = self._get(f"/api/v1/namespaces/{ns}/events", fieldSelector="type=Warning")["items"]
        return [{"reason": e.get("reason"), "message": e.get("message", "")[:200], "count": e.get("count", 1),
                 "object": e["involvedObject"].get("name")}
                for e in items if e["involvedObject"].get("name", "").startswith(prefix)]

    # --- writes; only the remediator calls these, and RBAC limits them to allowlisted namespaces ---
    def patch(self, path: str, body: Any, content_type: str) -> dict[str, Any]:
        r = self._c.patch(path, json=body, headers={"Content-Type": content_type})
        r.raise_for_status()
        return r.json()

    def request(self, method: str, path: str, body: Any = None) -> httpx.Response:
        return self._c.request(method, path, json=body)


def age_minutes(ts: str, now: datetime | None = None) -> float:
    t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return ((now or datetime.now(timezone.utc)) - t).total_seconds() / 60


class Sources(Protocol):
    """The facts playbooks may ask for. Each returns a value or raises."""
    def error_ratio(self, svc: dict) -> float | None: ...
    def error_ratio_1h_ago(self, svc: dict) -> float | None: ...
    def p95_latency(self, svc: dict) -> float | None: ...
    def rollout(self, svc: dict) -> dict | None: ...
    def warning_events(self, svc: dict) -> list[dict]: ...
    def restarts_15m(self, svc: dict) -> float: ...
    def cpu_throttle(self, svc: dict) -> float | None: ...
    def probes_down(self, svc: dict) -> list[str]: ...
    def min_cert_days(self, svc: dict) -> dict | None: ...


class LiveSources:
    def __init__(self, prom: Prometheus, kube: Kube | None):
        self.prom, self._kube = prom, kube

    @property
    def kube(self) -> Kube:
        if self._kube is None:
            raise SourceError("Kubernetes API not configured")
        return self._kube

    def error_ratio(self, svc):
        return self.prom.scalar("slo:request_errors:ratio_rate5m")

    def error_ratio_1h_ago(self, svc):
        return self.prom.scalar("slo:request_errors:ratio_rate5m offset 1h")

    def p95_latency(self, svc):
        return self.prom.scalar("slo:request_latency_seconds:p95_5m")

    def rollout(self, svc):
        rss = self.kube.replicasets(svc["namespace"], svc["deployment"])
        if not rss:
            return None
        newest = rss[0]["metadata"]
        image = rss[0]["spec"]["template"]["spec"]["containers"][0]["image"]
        replicas = self.kube.deployment(svc["namespace"], svc["deployment"])["spec"].get("replicas", 1)
        return {"revision": int(newest["annotations"][REVISION]), "image": image, "replicas": replicas,
                "age_min": round(age_minutes(newest["creationTimestamp"]), 1),
                "previous_image": rss[1]["spec"]["template"]["spec"]["containers"][0]["image"] if len(rss) > 1 else None}

    def warning_events(self, svc):
        return self.kube.warning_events(svc["namespace"], svc["deployment"])

    def restarts_15m(self, svc):
        return self.prom.scalar(
            f'sum(increase(kube_pod_container_status_restarts_total{{namespace="{svc["namespace"]}",'
            f'pod=~"{svc["deployment"]}-.*"}}[15m]))') or 0.0

    def cpu_throttle(self, svc):
        sel = f'namespace="{svc["namespace"]}",pod=~"{svc["deployment"]}-.*"'
        return self.prom.scalar(f"sum(rate(container_cpu_cfs_throttled_periods_total{{{sel}}}[5m])) / "
                                f"clamp_min(sum(rate(container_cpu_cfs_periods_total{{{sel}}}[5m])), 1)")

    def probes_down(self, svc):
        deps = svc.get("dependencies", [])
        return [r["labels"].get("target") for r in self.prom.query("max_over_time(netprobe_up[5m]) == 0")
                if r["labels"].get("target") in deps]

    def min_cert_days(self, svc):
        rows = [r for r in self.prom.query("netprobe_tls_cert_expiry_days")
                if r["labels"].get("target") in svc.get("dependencies", []) + svc.get("endpoints", [])]
        if not rows:
            return None
        low = min(rows, key=lambda r: r["value"])
        return {"target": low["labels"]["target"], "days": round(low["value"], 1)}


class StaticSources:
    """Facts from a dict (evals, demos). A missing key behaves like an outage of that source."""

    def __init__(self, facts: dict[str, Any]):
        self.facts = facts

    def __getattr__(self, name):
        def get(svc):
            if name not in self.facts:
                raise SourceError(f"{name}: source unavailable")
            return self.facts[name]
        return get
