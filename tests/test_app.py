import os

os.environ["ONCALL_AUTOSTART"] = "0"

import pytest
from fastapi.testclient import TestClient

from oncall_agent import app as appmod
from oncall_agent.fakes import FakeCluster
from oncall_agent.incidents import Incidents
from oncall_agent.remediate import LocalLock, Policy, Remediator
from oncall_agent.sources import StaticSources

CATALOG = {"slo-service": {"namespace": "slo", "deployment": "slo-service", "replicas": 2,
                           "alerts": ["SLOErrorBudgetFastBurn"], "dependencies": []}}
ALERT = {"alerts": [{"status": "firing", "fingerprint": "abc", "startsAt": "2026-10-27T10:00:00Z",
                     "labels": {"alertname": "SLOErrorBudgetFastBurn", "severity": "page"},
                     "annotations": {"runbook_url": "docs/runbook.md#sloerrorbudgetfastburn"}}]}


@pytest.fixture
def client(monkeypatch):
    cluster = FakeCluster()
    facts = {"error_ratio": 0.12, "error_ratio_1h_ago": 0.001, "p95_latency": 0.2, "warning_events": [],
             "restarts_15m": 0, "cpu_throttle": 0.01, "probes_down": [], "min_cert_days": None,
             "rollout": {"age_min": 8, "replicas": 2, "revision": 2}}
    sent = []
    monkeypatch.setenv("WEBHOOK_TOKEN", "t0ken")
    monkeypatch.setattr(appmod, "INCIDENTS", Incidents(CATALOG))
    monkeypatch.setattr(appmod, "SOURCES", StaticSources(facts))
    monkeypatch.setattr(appmod, "REMEDIATOR", Remediator(cluster.kube(), Policy(True, frozenset({"slo"})), LocalLock()))
    monkeypatch.setattr(appmod, "notify", sent.append)
    return TestClient(appmod.app), cluster, sent


def test_webhook_requires_token(client):
    c, _, _ = client
    assert c.post("/alertmanager", json=ALERT).status_code == 401
    assert c.post("/alertmanager", json=ALERT, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_alert_to_rollback_to_report_to_postmortem(client):
    c, cluster, sent = client
    auth = {"Authorization": "Bearer t0ken"}
    r = c.post("/alertmanager", json=ALERT, headers=auth)
    assert r.status_code == 202 and len(r.json()["triaging"]) == 1
    assert cluster.image == "app:1.4.0"                              # rolled back
    assert "Done automatically" in sent[0] and "revision 2 -> 1" in sent[0]

    assert c.post("/alertmanager", json=ALERT, headers=auth).json() == {"triaging": []}   # repeat: no re-triage
    inc_id = c.get("/incidents").json()[0]["id"]
    assert "rollout undo" in c.get(f"/incidents/{inc_id}/postmortem").text
    metrics = c.get("/metrics").text
    assert 'oncall_agent_remediations_total{action="rollback",executed="true"}' in metrics
