"""HTTP service: an Alertmanager webhook receiver that triages, remediates and reports.

POST /alertmanager                 Alertmanager webhook (bearer token)
GET  /incidents                    open and recently closed incidents
GET  /incidents/{id}               report + timeline
GET  /incidents/{id}/postmortem    post-mortem draft (markdown)
GET  /metrics                      Prometheus metrics about the bot itself
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import socket
import time

import httpx
import yaml
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from .diagnose import collect, diagnose
from .incidents import Incident, Incidents, postmortem, report, summarize
from .remediate import LeaseLock, LocalLock, Policy, Remediator
from .sources import Kube, LiveSources, Prometheus

log = logging.getLogger("oncall-agent")
logging.basicConfig(level=logging.INFO, format="%(message)s")

TRIAGES = Counter("oncall_agent_triages_total", "Incidents triaged", ["service", "diagnosis", "confidence"])
ACTIONS = Counter("oncall_agent_remediations_total", "Remediation outcomes", ["action", "executed"])
TRIAGE_SECONDS = Histogram("oncall_agent_triage_seconds", "Alert received -> report posted",
                           buckets=(0.5, 1, 2, 5, 10, 30))
SOURCE_ERRORS = Counter("oncall_agent_evidence_errors_total", "Evidence that could not be collected", ["fact"])


def load_catalog() -> dict:
    with open(os.environ.get("SERVICE_CATALOG", "services.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)["services"]


def build_runtime():
    catalog = load_catalog()
    in_cluster = bool(os.environ.get("KUBERNETES_SERVICE_HOST"))
    kube = Kube() if in_cluster else None
    sources = LiveSources(Prometheus(os.environ.get("PROMETHEUS_URL", "http://localhost:9090")), kube)
    policy = Policy(auto_enabled=os.environ.get("AUTO_REMEDIATE", "false") == "true",
                    namespaces=frozenset(filter(None, os.environ.get("REMEDIATE_NAMESPACES", "").split(","))))
    lock = LeaseLock(kube, os.environ.get("POD_NAMESPACE", "oncall"), "oncall-agent-remediation",
                     socket.gethostname()) if kube else LocalLock(held=False)
    return Incidents(catalog), sources, Remediator(kube, policy, lock)


app = FastAPI(title="oncall-agent")
INCIDENTS, SOURCES, REMEDIATOR = build_runtime() if os.environ.get("ONCALL_AUTOSTART", "1") == "1" else (None,) * 3


def notify(text: str) -> None:
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if url:
        try:
            httpx.post(url, json={"text": text}, timeout=5)
        except httpx.HTTPError as e:
            log.error(json.dumps({"event": "notify_failed", "error": str(e)}))
    log.info(json.dumps({"event": "report", "text": text}))


def llm_from_env():
    url, key = os.environ.get("LLM_BASE_URL"), os.environ.get("LLM_API_KEY")
    if not url:
        return None

    def call(prompt: str) -> str:
        r = httpx.post(f"{url.rstrip('/')}/chat/completions", timeout=20,
                       headers={"Authorization": f"Bearer {key}"},
                       json={"model": os.environ.get("LLM_MODEL", "gpt-4.1-mini"),
                             "messages": [{"role": "user", "content": prompt}]})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    return call


def triage(inc: Incident, sources, remediator: Remediator, catalog: dict, started: float) -> str:
    svc = catalog[inc.service]
    evidence = collect(sources, svc)
    for e in evidence.values():
        if e.error:
            SOURCE_ERRORS.labels(e.fact).inc()
    inc.diagnosis = diagnose(evidence)
    top = inc.diagnosis.top
    inc.note(f"triage: {top.key if top else 'unknown'} ({top.confidence if top else '-'})")
    TRIAGES.labels(inc.service, top.key if top else "unknown", top.confidence if top else "none").inc()

    plan = remediator.plan(inc.diagnosis, svc)
    try:
        inc.remediation = remediator.execute(plan)
    except Exception as e:   # a failed action is reported loudly, never swallowed
        inc.remediation = {"executed": False, "suggested_command": plan.command,
                           "why_not_automatic": [f"automatic attempt FAILED: {e}"]}
    if plan.action:
        ACTIONS.labels(plan.action, str(inc.remediation.get("executed", False)).lower()).inc()
        inc.note(("ran " if inc.remediation.get("executed") else "suggested ") + plan.command)
    text = report(inc)
    summary = summarize(inc, llm_from_env())
    if summary:
        text = summary + "\n\n" + text
    TRIAGE_SECONDS.observe(time.perf_counter() - started)
    return text


@app.post("/alertmanager", status_code=202)
async def alertmanager(request: Request, background: BackgroundTasks, authorization: str = Header(default="")):
    token = os.environ.get("WEBHOOK_TOKEN", "")
    if not token or not hmac.compare_digest(authorization, f"Bearer {token}"):
        raise HTTPException(401)
    started = time.perf_counter()
    payload = await request.json()
    triaged = []
    for inc, needs_triage in INCIDENTS.ingest(payload):
        if needs_triage:
            triaged.append(inc.id)
            background.add_task(lambda i=inc: notify(triage(i, SOURCES, REMEDIATOR, INCIDENTS.catalog, started)))
    return {"triaging": triaged}   # respond fast; Alertmanager retries on slow receivers


@app.get("/incidents")
def incidents():
    return [{"id": i.id, "service": i.service, "opened": i.opened, "resolved": i.resolved,
             "diagnosis": i.diagnosis.top.key if i.diagnosis and i.diagnosis.top else None}
            for i in list(INCIDENTS.open.values()) + INCIDENTS.closed[-50:]]


@app.get("/incidents/{incident_id}", response_class=PlainTextResponse)
def incident(incident_id: str):
    inc = INCIDENTS.find(incident_id)
    if not inc:
        raise HTTPException(404)
    return report(inc) + "\n\nTimeline:\n" + "\n".join(f"{t} {x}" for t, x in inc.timeline)


@app.get("/incidents/{incident_id}/postmortem", response_class=PlainTextResponse)
def incident_postmortem(incident_id: str):
    inc = INCIDENTS.find(incident_id)
    if not inc:
        raise HTTPException(404)
    return postmortem(inc)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/healthz")
def healthz():
    return {"ok": True}
