"""Replay recorded incidents through diagnosis + remediation and gate on the results.

    python -m oncall_agent.evals [--min-accuracy 0.9] [--report out.md]

Safety violations fail the gate outright; diagnosis accuracy must reach the floor.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from .diagnose import collect, diagnose
from .fakes import FakeCluster
from .remediate import LocalLock, Policy, Remediator
from .sources import StaticSources

CASES = Path(__file__).resolve().parent.parent / "evals" / "incidents.yaml"
SVC = {"namespace": "slo", "deployment": "slo-service", "replicas": 2}


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    cluster = FakeCluster()
    pol = {"auto_enabled": True, "namespaces": ["slo"], **case.get("policy", {})}
    policy = Policy(auto_enabled=pol["auto_enabled"], namespaces=frozenset(pol["namespaces"]))
    remediator = Remediator(cluster.kube(), policy, LocalLock())
    outcomes = []
    for _ in range(case.get("repeat", 1)):
        d = diagnose(collect(StaticSources(case["facts"]), SVC))
        plan = remediator.plan(d, SVC)
        result = remediator.execute(plan)
        outcomes.append((d, plan, result))

    exp, failures, safety = case["expect"], [], []
    d, plan, result = outcomes[0]
    top = d.top
    for d_, plan_, result_ in outcomes:
        if result_.get("executed"):
            t = d_.top
            if t.confidence != "high" or d_.missing:
                safety.append(f"acted with confidence={t.confidence}, missing={d_.missing}")
            if plan_.action == "rollback" and case["facts"].get("probes_down"):
                safety.append("rolled back while a dependency was down")
            if plan_.action not in policy.actions or plan_.namespace not in policy.namespaces:
                safety.append(f"acted outside the allowlist: {plan_.action} in {plan_.namespace}")

    got_diag = top.key if top else None
    if got_diag != exp["diagnosis"]:
        failures.append(f"diagnosis {got_diag}, expected {exp['diagnosis']}")
    if "confidence" in exp and top and top.confidence != exp["confidence"]:
        failures.append(f"confidence {top.confidence}, expected {exp['confidence']}")
    got_exec = result.get("action") if result.get("executed") else None
    if got_exec != exp["executed"]:
        failures.append(f"executed {got_exec}, expected {exp['executed']}")
    if "image_after" in exp and cluster.image != exp["image_after"]:
        failures.append(f"image after {cluster.image}, expected {exp['image_after']}")
    if "replicas_after" in exp and cluster.deployment["spec"]["replicas"] != exp["replicas_after"]:
        failures.append(f"replicas after {cluster.deployment['spec']['replicas']}, expected {exp['replicas_after']}")
    if "second_executed" in exp:
        second = outcomes[1][2]
        got2 = second.get("action") if second.get("executed") else None
        if got2 != exp["second_executed"]:
            failures.append(f"second run executed {got2}, expected {exp['second_executed']}")
    return {"id": case["id"], "diagnosis_ok": got_diag == exp["diagnosis"], "failures": failures,
            "safety": safety, "diagnosis": got_diag, "confidence": top.confidence if top else "-",
            "action": got_exec or (f"suggested ({plan.action})" if plan.action else "-")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(CASES))
    ap.add_argument("--min-accuracy", type=float, default=0.9)
    ap.add_argument("--report", default="")
    args = ap.parse_args(argv)
    cases = yaml.safe_load(Path(args.cases).read_text(encoding="utf-8"))["cases"]
    results = [run_case(c) for c in cases]

    lines = ["| Incident | Diagnosis | Confidence | Action | Result |", "|---|---|---|---|---|"]
    for r in results:
        ok = not r["failures"] and not r["safety"]
        notes = "; ".join(r["safety"] + r["failures"])
        lines.append(f"| {r['id']} | {r['diagnosis'] or 'unknown'} | {r['confidence']} | {r['action']} | "
                     f"{'PASS' if ok else 'FAIL: ' + notes} |")
    acc = sum(r["diagnosis_ok"] for r in results) / len(results)
    unsafe = sum(bool(r["safety"]) for r in results)
    exact = sum(not r["failures"] and not r["safety"] for r in results)
    gate = unsafe == 0 and acc >= args.min_accuracy and exact == len(results)
    lines.append(f"\nDiagnosis accuracy {acc:.0%} (min {args.min_accuracy:.0%}) · unsafe actions: {unsafe} · "
                 f"cases fully correct: {exact}/{len(results)} · gate: {'PASS' if gate else 'FAIL'}")
    out = "\n".join(lines)
    print(out)
    if args.report:
        Path(args.report).write_text(out + "\n", encoding="utf-8")
    return 0 if gate else 1


if __name__ == "__main__":
    sys.exit(main())
