"""Alerts in, incidents out.

Alertmanager re-sends a firing group every repeat_interval. Those repeats must
not re-run triage or re-page anyone, so alerts are keyed by fingerprint and
only a new alert or a status change adds to an incident's timeline.
"""
from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .diagnose import Diagnosis


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Incident:
    id: str
    service: str
    opened: str
    alerts: dict[str, dict[str, Any]] = field(default_factory=dict)     # fingerprint -> alert
    timeline: list[tuple[str, str]] = field(default_factory=list)
    diagnosis: Diagnosis | None = None
    remediation: dict[str, Any] | None = None
    resolved: str | None = None

    def note(self, text: str, at: str | None = None) -> None:
        self.timeline.append((at or now_iso(), text))


class Incidents:
    def __init__(self, catalog: dict[str, dict]):
        self.catalog = catalog
        self.open: dict[str, Incident] = {}      # service -> open incident
        self.closed: list[Incident] = []
        self._lock = threading.Lock()

    def service_for(self, labels: dict[str, str]) -> str | None:
        if labels.get("service") in self.catalog:
            return labels["service"]
        for name, svc in self.catalog.items():
            if labels.get("alertname") in svc.get("alerts", []) or labels.get("target") in svc.get("dependencies", []):
                return name
        return None

    def ingest(self, payload: dict[str, Any]) -> list[tuple[Incident, bool]]:
        """Returns (incident, needs_triage) for each incident this payload touched."""
        touched: dict[str, tuple[Incident, bool]] = {}
        with self._lock:
            for a in payload.get("alerts", []):
                labels = a.get("labels", {})
                service = self.service_for(labels)
                if service is None:
                    continue
                fp = a.get("fingerprint") or str(sorted(labels.items()))
                inc = self.open.get(service)
                if inc is None:
                    if a.get("status") != "firing":
                        continue        # a resolve for something we never saw open
                    inc = self.open[service] = Incident(uuid.uuid4().hex[:8], service, now_iso())
                prev = inc.alerts.get(fp)
                if prev and prev["status"] == a.get("status"):
                    touched.setdefault(service, (inc, False))   # repeat notification: nothing new
                    continue
                inc.alerts[fp] = {"name": labels.get("alertname"), "status": a.get("status"),
                                  "severity": labels.get("severity"), "startsAt": a.get("startsAt"),
                                  "summary": a.get("annotations", {}).get("summary", ""),
                                  "runbook": a.get("annotations", {}).get("runbook_url", "")}
                inc.note(f"{labels.get('alertname')} {a.get('status')}", a.get("startsAt") if
                         a.get("status") == "firing" else a.get("endsAt"))
                new_firing = a.get("status") == "firing"
                touched[service] = (inc, touched.get(service, (inc, False))[1] or new_firing)
                if all(x["status"] == "resolved" for x in inc.alerts.values()):
                    inc.resolved = now_iso()
                    inc.note("all alerts resolved")
                    self.closed.append(self.open.pop(service))
        return list(touched.values())

    def find(self, incident_id: str) -> Incident | None:
        return next((i for i in list(self.open.values()) + self.closed if i.id == incident_id), None)


def describe(e) -> str:
    if e.error:
        return f"unavailable ({e.error})"
    v = e.value
    if isinstance(v, float):
        return f"{v:.4g}"
    if isinstance(v, list):
        return ", ".join(str(x.get("reason", x)) if isinstance(x, dict) else str(x) for x in v) or "none"
    if isinstance(v, dict):
        return ", ".join(f"{k}={val}" for k, val in v.items())
    return "none" if v is None else str(v)


def report(inc: Incident) -> str:
    """The message on-call reads first. Leads with the conclusion and the next step."""
    d, r = inc.diagnosis, inc.remediation or {}
    firing = [a for a in inc.alerts.values() if a["status"] == "firing"]
    lines = [f"*{inc.service}*: {', '.join(a['name'] for a in firing) or 'alerts'} (incident {inc.id})"]
    if d and d.top:
        t = d.top
        lines.append(f"*Likely cause ({t.confidence} confidence):* {t.title}. "
                     f"Because {'; '.join(t.held)} [{', '.join(t.evidence)}].")
        if t.against:
            lines.append(f"*But:* {'; '.join(t.against)}.")
        lines.append(f"*Next step:* {t.advice}")
        for alt in d.findings[1:3]:
            lines.append(f"_Also possible ({alt.confidence}):_ {alt.title}")
    elif d and len(d.missing) == len(d.evidence):
        lines.append("*Likely cause:* unknown. No evidence could be collected (are Prometheus and the "
                     "Kubernetes API reachable?). Work from the runbook.")
    else:
        lines.append("*Likely cause:* unknown. No playbook matched; evidence is below.")
    if r.get("executed"):
        lines.append(f"*Done automatically:* `{r['command_equivalent']}` "
                     f"{'(revision ' + str(r['from_revision']) + ' -> ' + str(r['to_revision']) + ')' if 'to_revision' in r else ''}")
    elif r.get("suggested_command"):
        lines.append(f"*Suggested:* `{r['suggested_command']}` (not run: {'; '.join(r['why_not_automatic'])})")
    if d:
        if d.missing:
            lines.append(f"*Could not check:* {', '.join(d.missing)}")
        lines.append("Evidence: " + " | ".join(f"{e.id} {e.fact}: {describe(e)}" for e in d.evidence.values()))
    runbooks = {a["runbook"] for a in firing if a["runbook"]}
    if runbooks:
        lines.append("Runbook: " + ", ".join(sorted(runbooks)))
    return "\n".join(lines)


def summarize(inc: Incident, llm: Callable[[str], str] | None) -> str | None:
    """Optional two-sentence plain-English summary. It must cite only evidence ids that exist,
    otherwise it is dropped; the deterministic report never depends on it."""
    if llm is None or not inc.diagnosis:
        return None
    try:
        text = llm("Summarise this incident triage for an on-call engineer in two sentences. "
                   "Cite evidence ids like [E3] for every claim. Do not add facts.\n\n" + report(inc))
    except Exception:
        return None
    cited = set(re.findall(r"\bE\d+\b", text))
    known = {e.id for e in inc.diagnosis.evidence.values()}
    return text.strip() if cited and cited <= known else None


def postmortem(inc: Incident) -> str:
    """A blameless post-mortem draft, pre-filled from what the bot saw. Humans fill in the rest."""
    d = inc.diagnosis
    t = d.top if d else None
    duration = ""
    if inc.resolved:
        delta = datetime.fromisoformat(inc.resolved.replace("Z", "+00:00")) - \
            datetime.fromisoformat(inc.opened.replace("Z", "+00:00"))
        duration = f" ({int(delta.total_seconds() // 60)} min)"
    return "\n".join([
        f"# Post-mortem: {inc.service} incident {inc.id}",
        "",
        f"**Status:** draft · **Opened:** {inc.opened} · **Resolved:** {inc.resolved or 'ongoing'}{duration}",
        "",
        "## Summary",
        f"{t.title} (bot diagnosis, {t.confidence} confidence; confirm or correct)." if t else "_To fill in._",
        "",
        "## Impact",
        "_Which users, how many requests failed, how much error budget was spent._",
        "",
        "## Timeline (UTC)",
        *[f"- {ts} {text}" for ts, text in inc.timeline],
        "",
        "## What the triage bot found",
        *([f"- {s}" for s in t.held] if t else ["- No playbook matched."]),
        *([f"- Evidence that could not be collected: {', '.join(d.missing)}"] if d and d.missing else []),
        "",
        "## Remediation",
        (f"- Automatic: `{inc.remediation['command_equivalent']}`" if inc.remediation and inc.remediation.get("executed")
         else f"- Suggested, not automatic: `{(inc.remediation or {}).get('suggested_command', 'n/a')}`"),
        "",
        "## Contributing factors",
        "_Why did this happen, and why wasn't it caught earlier? (No names; systems and decisions.)_",
        "",
        "## Action items",
        "| Action | Type (prevent / detect / mitigate) | Owner | Ticket |",
        "|---|---|---|---|",
        "| | | | |",
    ])
