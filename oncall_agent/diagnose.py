"""Evidence collection and rule-based diagnosis.

Diagnosis is deterministic on purpose. An on-call tool has to work during the
incidents where the LLM API is down or slow, and its reasoning has to be
checkable at 3am. Each hypothesis lists the facts that must hold, the facts
that make it stronger, and the facts that argue against it; every conclusion
points at the evidence ids it used.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any, Callable

from .sources import Sources

FACTS = ["error_ratio", "error_ratio_1h_ago", "p95_latency", "rollout", "warning_events", "restarts_15m",
         "cpu_throttle", "probes_down", "min_cert_days"]


@dataclass
class Evidence:
    id: str
    fact: str
    value: Any = None
    error: str | None = None


def collect(sources: Sources, svc: dict, timeout_s: float = 4.0) -> dict[str, Evidence]:
    """Fetch every fact in parallel. A slow or failing source becomes an error, never an exception."""
    out: dict[str, Evidence] = {}
    pool = ThreadPoolExecutor(max_workers=len(FACTS))
    deadline = time.monotonic() + timeout_s       # one budget for all facts, not one per fact
    try:
        futures = {f: pool.submit(getattr(sources, f), svc) for f in FACTS}
        for n, (fact, fut) in enumerate(futures.items(), 1):
            try:
                out[fact] = Evidence(f"E{n}", fact, fut.result(timeout=max(deadline - time.monotonic(), 0)))
            except FutureTimeout:
                out[fact] = Evidence(f"E{n}", fact, error=f"timed out after {timeout_s}s")
            except Exception as e:
                out[fact] = Evidence(f"E{n}", fact, error=str(e) or type(e).__name__)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)   # don't let a hung source hold up triage
    return out


Pred = Callable[[dict[str, Any]], bool]


@dataclass
class Signal:
    text: str
    facts: tuple[str, ...]
    test: Pred


@dataclass
class Hypothesis:
    key: str
    title: str
    requires: list[Signal]
    supports: list[Signal] = field(default_factory=list)
    against: list[Signal] = field(default_factory=list)
    action: str | None = None   # remediation name, if one exists
    advice: str = ""


def _v(f, name, default=None):
    return f.get(name, default) if f.get(name) is not None else default


RECENT = Signal("a rollout happened in the last 60 minutes", ("rollout",),
                lambda f: (_v(f, "rollout") or {}).get("age_min", 1e9) <= 60)
ERRORS_JUMPED = Signal("error ratio is 5x or more higher than an hour ago", ("error_ratio", "error_ratio_1h_ago"),
                       lambda f: _v(f, "error_ratio", 0) >= 0.01 and
                       _v(f, "error_ratio", 0) >= 5 * max(_v(f, "error_ratio_1h_ago", 0), 0.001))
CRASHING = Signal("containers restarted 3+ times in 15 minutes", ("restarts_15m",),
                  lambda f: _v(f, "restarts_15m", 0) >= 3)
DEP_DOWN = Signal("a dependency fails every probe", ("probes_down",), lambda f: bool(_v(f, "probes_down", [])))
OOM = Signal("pods were OOM-killed", ("warning_events",),
             lambda f: any(e["reason"] in ("OOMKilling", "OOMKilled") for e in _v(f, "warning_events", [])))
THROTTLED = Signal("CPU is throttled more than 25% of the time", ("cpu_throttle",),
                   lambda f: _v(f, "cpu_throttle", 0) > 0.25)
SLOW = Signal("p95 latency is above 300ms", ("p95_latency",), lambda f: _v(f, "p95_latency", 0) > 0.3)
CERT = Signal("a certificate expires within 7 days", ("min_cert_days",),
              lambda f: (_v(f, "min_cert_days") or {}).get("days", 1e9) < 7)
IMAGE_PULL = Signal("image pull is failing", ("warning_events",),
                    lambda f: any(e["reason"] in ("Failed", "ErrImagePull", "ImagePullBackOff")
                                  and "image" in e["message"].lower() for e in _v(f, "warning_events", [])))
NO_ROLLOUT = Signal("no rollout in the last 60 minutes", ("rollout",),
                    lambda f: (_v(f, "rollout") or {}).get("age_min", 1e9) > 60)

HYPOTHESES = [
    Hypothesis("bad_deploy", "The most recent rollout broke the service",
               requires=[RECENT], supports=[ERRORS_JUMPED, CRASHING, IMAGE_PULL], against=[DEP_DOWN],
               action="rollback", advice="Roll back to the previous revision, then compare the two images."),
    Hypothesis("dependency_down", "A dependency is down; this service is failing because of it",
               requires=[DEP_DOWN], supports=[ERRORS_JUMPED, SLOW],
               advice="Page the dependency's owner. Rolling back or scaling this service will not help."),
    Hypothesis("saturation", "The service is out of CPU or memory",
               requires=[], supports=[OOM, THROTTLED, SLOW], against=[RECENT, DEP_DOWN],
               action="scale_up", advice="Add replicas now; then look at limits and the traffic increase."),
    Hypothesis("crashloop", "Pods are crash-looping without a recent rollout (config, secret or node issue)",
               requires=[CRASHING, NO_ROLLOUT], supports=[OOM],
               advice="Read the logs of the previous container: kubectl logs --previous."),
    Hypothesis("cert_expiry", "A TLS certificate is about to expire or has expired",
               requires=[CERT], advice="Renew the certificate; check why automatic renewal didn't run."),
]


@dataclass
class Finding:
    key: str
    title: str
    confidence: str            # high / medium / low
    score: int
    held: list[str]
    against: list[str]
    evidence: list[str]        # evidence ids
    action: str | None
    advice: str


@dataclass
class Diagnosis:
    findings: list[Finding]
    evidence: dict[str, Evidence]
    missing: list[str]         # facts we couldn't get; shown so nobody mistakes "unknown" for "fine"

    @property
    def top(self) -> Finding | None:
        return self.findings[0] if self.findings else None


def diagnose(evidence: dict[str, Evidence]) -> Diagnosis:
    facts = {k: e.value for k, e in evidence.items() if e.error is None}
    missing = [k for k, e in evidence.items() if e.error]

    def ids(signals):
        return sorted({evidence[f].id for s in signals for f in s.facts if f in evidence})

    def holds(s: Signal) -> bool:
        return all(f in facts for f in s.facts) and s.test(facts)

    findings = []
    for h in HYPOTHESES:
        if not all(holds(s) for s in h.requires):
            continue
        sup = [s for s in h.supports if holds(s)]
        con = [s for s in h.against if holds(s)]
        if not h.requires and not sup:
            continue        # a hypothesis with no hard requirement needs at least one positive signal
        score = 2 * len(h.requires) + len(sup) - 2 * len(con)
        if con:
            confidence = "low"
        elif sup and (h.requires or len(sup) >= 2):
            confidence = "high"
        else:
            confidence = "medium"
        findings.append(Finding(h.key, h.title, confidence, score,
                                [s.text for s in h.requires + sup], [s.text for s in con],
                                ids(h.requires + sup + con), h.action, h.advice))
    rank = {"high": 2, "medium": 1, "low": 0}
    findings.sort(key=lambda f: (rank[f.confidence], f.score), reverse=True)
    return Diagnosis(findings, evidence, missing)
