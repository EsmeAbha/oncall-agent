import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from oncall_agent import diagnose as dmod
from oncall_agent import evals
from oncall_agent.diagnose import collect, diagnose
from oncall_agent.fakes import FakeCluster
from oncall_agent.incidents import Incidents, postmortem, report, summarize
from oncall_agent.remediate import LeaseLock, LocalLock, Plan, Policy, Remediator, rollback
from oncall_agent.sources import LiveSources, Prometheus, StaticSources

SVC = {"namespace": "slo", "deployment": "slo-service", "replicas": 2,
       "dependencies": ["https://pay/healthz"], "endpoints": []}


# --- sources ---

def prom_returning(results_by_query):
    def handler(req):
        q = req.url.params["query"]
        rows = results_by_query.get(q, [])
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": labels, "value": [0, str(v)]} for labels, v in rows]}})
    return Prometheus("http://prom", client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_live_sources_read_prometheus_and_kubernetes():
    cluster = FakeCluster()
    prom = prom_returning({
        "slo:request_errors:ratio_rate5m": [({}, 0.12)],
        "max_over_time(netprobe_up[5m]) == 0": [({"target": "https://pay/healthz"}, 0),
                                                 ({"target": "https://unrelated"}, 0)]})
    live = LiveSources(prom, cluster.kube())
    assert live.error_ratio(SVC) == 0.12
    assert live.probes_down(SVC) == ["https://pay/healthz"]       # only this service's dependencies
    r = live.rollout(SVC)
    assert r["revision"] == 2 and r["image"] == "app:1.5.0" and r["previous_image"] == "app:1.4.0"
    assert r["replicas"] == 2


def test_without_kubernetes_the_kube_facts_are_unavailable_not_fatal():
    live = LiveSources(prom_returning({}), None)
    ev = collect(live, SVC, timeout_s=2)
    assert ev["rollout"].error and ev["warning_events"].error
    assert ev["error_ratio"].error is None


def test_slow_or_broken_sources_cannot_stall_triage():
    class Slow(StaticSources):
        def __getattr__(self, name):
            if name == "p95_latency":
                return lambda svc: time.sleep(3)
            if name == "rollout":
                def boom(svc):
                    raise ConnectionError("api server unreachable")
                return boom
            return super().__getattr__(name)

    t0 = time.perf_counter()
    ev = collect(Slow({"error_ratio": 0.1}), SVC, timeout_s=0.3)
    assert time.perf_counter() - t0 < 1.5
    assert "timed out" in ev["p95_latency"].error and "unreachable" in ev["rollout"].error
    assert "p95_latency" in diagnose(ev).missing


# --- remediation ---

def test_rollback_restores_previous_template_like_kubectl():
    cluster = FakeCluster()
    out = rollback(cluster.kube(), "slo", "slo-service")
    assert out == {"from_revision": 2, "to_revision": 1, "to_image": "app:1.4.0"}
    assert cluster.image == "app:1.4.0"
    assert "pod-template-hash" not in cluster.deployment["spec"]["template"]["metadata"]["labels"]


def test_scale_up_is_bounded():
    cluster = FakeCluster(replicas=8)
    facts = {"cpu_throttle": 0.7, "p95_latency": 0.9, "warning_events": [], "probes_down": [],
             "rollout": {"age_min": 999, "replicas": 8}}
    d = diagnose(collect(StaticSources({**facts, **{k: None for k in dmod.FACTS if k not in facts}}), SVC))
    plan = Remediator(cluster.kube(), Policy(True, frozenset({"slo"}), max_replicas=10), LocalLock()).plan(d, SVC)
    assert plan.params["replicas"] == 10          # ceil(8 * 1.5) = 12, capped at 10


def test_lease_only_one_holder_and_takeover_after_expiry():
    cluster = FakeCluster()
    clock = {"t": datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)}
    now = lambda: clock["t"]
    a = LeaseLock(cluster.kube(), "oncall", "remediation", "pod-a", ttl_s=30, now=now)
    b = LeaseLock(cluster.kube(), "oncall", "remediation", "pod-b", ttl_s=30, now=now)
    assert a.acquire()
    assert not b.acquire()                        # a holds a live lease
    clock["t"] += timedelta(seconds=10)
    assert a.acquire()                            # renewal
    clock["t"] += timedelta(seconds=31)
    assert b.acquire()                            # a stopped renewing: b takes over
    assert not a.acquire()


def test_lease_write_conflict_loses_instead_of_double_acquiring():
    cluster = FakeCluster()
    kube = cluster.kube()
    LeaseLock(kube, "oncall", "r", "pod-a", ttl_s=1, now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)).acquire()
    stale = kube.request("GET", "/apis/coordination.k8s.io/v1/namespaces/oncall/leases/r").json()
    assert LeaseLock(kube, "oncall", "r", "pod-b").acquire()      # b takes the expired lease
    stale["spec"]["holderIdentity"] = "pod-c"                       # c writes with what it read earlier
    assert kube.request("PUT", "/apis/coordination.k8s.io/v1/namespaces/oncall/leases/r", stale).status_code == 409


def test_lost_lease_means_suggest_not_act():
    cluster = FakeCluster()
    r = Remediator(cluster.kube(), Policy(True, frozenset({"slo"})), LocalLock(held=False))
    out = r.execute(Plan("rollback", "slo", "slo-service", "kubectl ...", True))
    assert out["executed"] is False and "lease" in out["why_not_automatic"][0]
    assert cluster.image == "app:1.5.0"


# --- incidents ---

def firing(name="SLOErrorBudgetFastBurn", status="firing", fp="f1"):
    return {"alerts": [{"status": status, "fingerprint": fp, "labels": {"alertname": name, "severity": "page"},
                        "annotations": {"summary": "burning", "runbook_url": "docs/runbook.md#x"},
                        "startsAt": "2026-10-27T10:00:00Z", "endsAt": "2026-10-27T10:40:00Z"}]}


def test_repeat_notifications_do_not_retrigger_and_resolve_closes():
    incs = Incidents({"slo-service": {"alerts": ["SLOErrorBudgetFastBurn"]}})
    [(inc, new)] = incs.ingest(firing())
    assert new
    [(again, new2)] = incs.ingest(firing())
    assert again is inc and not new2 and len(inc.timeline) == 1
    incs.ingest(firing(status="resolved"))
    assert inc.resolved and not incs.open and incs.closed == [inc]
    assert incs.ingest({"alerts": [{"status": "firing", "labels": {"alertname": "Unrelated"}}]}) == []


def test_report_postmortem_and_grounded_summary():
    incs = Incidents({"slo-service": {"alerts": ["SLOErrorBudgetFastBurn"]}})
    [(inc, _)] = incs.ingest(firing())
    inc.diagnosis = diagnose(collect(StaticSources({
        "error_ratio": 0.12, "error_ratio_1h_ago": 0.001, "rollout": {"age_min": 9, "replicas": 2},
        "probes_down": [], "warning_events": []}), SVC))
    text = report(inc)
    assert "Likely cause (high confidence)" in text and "Could not check" in text and "docs/runbook.md#x" in text
    assert "## Timeline (UTC)" in postmortem(inc)
    assert summarize(inc, lambda p: "Deploy broke it [E4] [E1].") is not None
    assert summarize(inc, lambda p: "Deploy broke it [E99].") is None      # cites evidence that doesn't exist
    assert summarize(inc, lambda p: "Deploy broke it.") is None            # cites nothing
    assert summarize(inc, lambda p: 1 / 0) is None                         # LLM down: report still goes out


# --- evals: the gate passes, and fails when a safety rule is removed ---

def test_incident_replay_gate_passes():
    assert evals.main([]) == 0


def test_gate_fails_if_dependency_check_is_removed(monkeypatch):
    bad = next(h for h in dmod.HYPOTHESES if h.key == "bad_deploy")
    monkeypatch.setattr(bad, "against", [])
    assert evals.main([]) == 1


def test_gate_flags_unsafe_actions_if_the_policy_is_bypassed(monkeypatch):
    real_plan = Remediator.plan

    def reckless(self, d, svc):
        p = real_plan(self, d, svc)
        p.auto, p.blocked_by = p.action is not None and bool(p.command), []
        return p

    monkeypatch.setattr(Remediator, "plan", reckless)
    cases = {c["id"]: c for c in evals.yaml.safe_load(evals.CASES.read_text(encoding="utf-8"))["cases"]}
    assert evals.run_case(cases["prometheus-down-during-bad-deploy"])["safety"]
    assert evals.main([]) == 1
