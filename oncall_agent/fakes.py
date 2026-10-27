"""An in-memory Kubernetes API good enough for remediation: deployments, ReplicaSets, scale, Leases.
Used by the tests and by the incident-replay evals."""
from __future__ import annotations

import copy
import json
from typing import Any

import httpx

from .sources import REVISION, Kube


class FakeCluster:
    def __init__(self, ns: str = "slo", name: str = "slo-service", images: tuple[str, ...] = ("app:1.4.0", "app:1.5.0"),
                 replicas: int = 2):
        self.ns, self.name = ns, name
        self.calls: list[tuple[str, str]] = []
        self.leases: dict[str, dict[str, Any]] = {}
        self.rv = 0
        self.replicasets = [self._rs(i + 1, img) for i, img in enumerate(images)]
        self.deployment = {"metadata": {"name": name, "namespace": ns},
                           "spec": {"replicas": replicas,
                                    "template": copy.deepcopy(self.replicasets[-1]["spec"]["template"])}}
        self.deployment["spec"]["template"]["metadata"]["labels"].pop("pod-template-hash")

    def _rs(self, rev: int, image: str) -> dict[str, Any]:
        return {"metadata": {"name": f"{self.name}-{rev:04x}", "creationTimestamp": "2026-10-27T10:00:00Z",
                             "annotations": {REVISION: str(rev)},
                             "ownerReferences": [{"kind": "Deployment", "name": self.name}]},
                "spec": {"template": {"metadata": {"labels": {"app": self.name, "pod-template-hash": f"h{rev}"}},
                                      "spec": {"containers": [{"name": "app", "image": image}]}}}}

    @property
    def image(self) -> str:
        return self.deployment["spec"]["template"]["spec"]["containers"][0]["image"]

    def handler(self, req: httpx.Request) -> httpx.Response:
        path, method = req.url.path, req.method
        self.calls.append((method, path))
        apps = f"/apis/apps/v1/namespaces/{self.ns}"
        leases = "/apis/coordination.k8s.io/v1/namespaces/"
        if method == "GET" and path == f"{apps}/replicasets":
            return httpx.Response(200, json={"items": self.replicasets})
        if path == f"{apps}/deployments/{self.name}":
            if method == "GET":
                return httpx.Response(200, json=self.deployment)
            if method == "PATCH":   # json-patch replace /spec/template, as rollout undo does
                op = json.loads(req.content)[0]
                assert op["path"] == "/spec/template" and req.headers["content-type"] == "application/json-patch+json"
                self.deployment["spec"]["template"] = op["value"]
                self.rv += 1
                img = op["value"]["spec"]["containers"][0]["image"]
                self.replicasets.append(self._rs(len(self.replicasets) + 1, img))
                return httpx.Response(200, json=self.deployment)
        if method == "PATCH" and path == f"{apps}/deployments/{self.name}/scale":
            self.deployment["spec"]["replicas"] = json.loads(req.content)["spec"]["replicas"]
            return httpx.Response(200, json={"spec": {"replicas": self.deployment["spec"]["replicas"]}})
        if path.startswith(leases):
            return self._lease(req, path.rsplit("/", 1)[-1])
        return httpx.Response(404, json={"reason": "NotFound"})

    def _lease(self, req: httpx.Request, name: str) -> httpx.Response:
        if req.method == "GET":
            lease = self.leases.get(name)
            return httpx.Response(200, json=lease) if lease else httpx.Response(404)
        body = json.loads(req.content)
        if req.method == "POST":
            name = body["metadata"]["name"]
            if name in self.leases:
                return httpx.Response(409)
            self.rv += 1
            body["metadata"]["resourceVersion"] = str(self.rv)
            self.leases[name] = body
            return httpx.Response(201, json=body)
        if req.method == "PUT":
            if body["metadata"].get("resourceVersion") != self.leases[name]["metadata"]["resourceVersion"]:
                return httpx.Response(409)   # optimistic concurrency: someone wrote since we read
            self.rv += 1
            body["metadata"]["resourceVersion"] = str(self.rv)
            self.leases[name] = body
            return httpx.Response(200, json=body)
        return httpx.Response(405)

    def kube(self) -> Kube:
        return Kube(client=httpx.Client(base_url="https://k8s.test", transport=httpx.MockTransport(self.handler)))
