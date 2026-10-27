# oncall-agent

An alert-triage bot for Kubernetes services. When Alertmanager pages, it gathers evidence from Prometheus and the Kubernetes API, works out the likely cause, and posts a report to the incident channel within seconds. Each report leads with the conclusion and the next step, and cites its evidence. For the few causes where it's safe, it can also fix the problem itself, under strict limits.

It triages the alerts from [`k8s-slo-service`](https://github.com/EsmeAbha/k8s-slo-service) (SLO burn-rate alerts) and [`netprobe`](https://github.com/EsmeAbha/netprobe) (dependency probes and certificate expiry).

```
Alertmanager ──► /alertmanager ──► group and de-duplicate ──► collect evidence (parallel, time-boxed)
                                                              │  Prometheus: error ratio now vs 1h ago, p95,
                                                              │  restarts, CPU throttling, probes, cert expiry
                                                              │  Kubernetes: rollouts, warning events
                                                              ▼
                              diagnose (rules) ──► remediate or suggest ──► report to Slack ──► post-mortem draft
```

## What a report looks like

```
slo-service: SLOErrorBudgetFastBurn (incident 6578ef76)
Likely cause (high confidence): The most recent rollout broke the service. Because a rollout happened in
  the last 60 minutes; error ratio is 5x or more higher than an hour ago [E1, E2, E4].
Next step: Roll back to the previous revision, then compare the two images.
Done automatically: `kubectl -n slo rollout undo deployment/slo-service` (revision 2 -> 1)
Evidence: E1 error_ratio: 0.12 | E2 error_ratio_1h_ago: 0.001 | E4 rollout: revision=2, image=app:1.5.0, age_min=12 ...
Runbook: docs/runbook.md#sloerrorbudgetfastburn
```

## Design decisions

- **The diagnosis doesn't depend on an LLM.** An on-call tool must work during the incidents where the LLM API is down, and its reasoning must be checkable at 3am. Each hypothesis lists the facts it requires, the facts that support it and the facts that **argue against** it. For example, "a recent deploy" is downgraded when a dependency is also down, because rolling back wouldn't help then. An LLM can add a two-sentence summary, but it's discarded unless every claim cites an evidence id that exists.
- **Partial failure is normal.** Each fact is fetched in parallel within one time budget. A source that's slow or down becomes "could not check", never a crash or a stall, and the report lists what it couldn't see, so "unknown" is never mistaken for "fine".
- **Repeats don't re-page.** Alertmanager re-sends firing alerts every repeat interval. Alerts are keyed by fingerprint, so only a new alert or a status change triggers triage.

## Automatic remediation, and its limits

Only `rollback` (exactly what `kubectl rollout undo` does: the previous ReplicaSet's pod template is copied back) and `scale_up` (×1.5, capped) can run automatically. And only when **all** of these hold:

| Guard | Why |
|---|---|
| Kill switch `AUTO_REMEDIATE` (default **off**) | Start in suggest-only mode; turn it on after reviewing what it would have done |
| Action and namespace on the allowlist | Enforced twice: in code, and in RBAC (see below) |
| High confidence, nothing arguing against it | A medium hunch gets a suggestion, not an action |
| No missing evidence | With half the picture, a human decides |
| 30-minute cooldown per deployment | If the rollback didn't fix it, escalate rather than flap |
| At most 3 automatic actions per hour | Limits the blast radius of a bad rule |
| Holds the Kubernetes `Lease` | Two replicas receive every alert; leader election (optimistic concurrency on `resourceVersion`) means only one acts |

When any guard blocks an action, the report shows the exact command and every reason it wasn't run.

## Least privilege (RBAC)

`deploy/kubernetes/oncall-agent.yaml` gives the bot:
- read access to deployments, ReplicaSets, pods and events;
- `patch` on deployments only in allowlisted namespaces;
- one named Lease.

It has **no access to Secrets** and no `exec`. CI applies the manifest to a real kind cluster and checks with `kubectl auth can-i` that each of these holds, and that, for example, patching in `kube-system` and reading Secrets are denied. The pod also runs as non-root with a read-only filesystem and all capabilities dropped. A NetworkPolicy allows calls only from the monitoring namespace.

## Incident replays: the CI gate

`evals/incidents.yaml` replays 11 incident shapes through diagnosis and remediation against an in-memory Kubernetes API:
- bad deploy;
- crash loop after a deploy;
- **a deploy that coincides with a dependency outage**;
- OOM and CPU throttling;
- crash loop with no deploy;
- certificate expiry;
- **Prometheus down during a bad deploy**;
- kill switch off;
- namespace not on the allowlist;
- repeat alert hitting the cooldown;
- a noisy alert with nothing wrong.

```
python -m oncall_agent.evals
Diagnosis accuracy 100% (min 90%) · unsafe actions: 0 · cases fully correct: 11/11 · gate: PASS
```

Any unsafe action fails the gate, for example acting on medium confidence or missing evidence, or rolling back during a dependency outage. The gate is tested too: `tests/` removes the dependency-outage rule, or bypasses the policy, and asserts that the gate then **fails**.

## Run it

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q                                  # 15 tests
python -m oncall_agent.evals               # incident replays

WEBHOOK_TOKEN=... PROMETHEUS_URL=http://localhost:9090 uvicorn oncall_agent.app:app --port 8080
```

| Endpoint | |
|---|---|
| `POST /alertmanager` | Alertmanager webhook (bearer token); replies immediately, triages in the background |
| `GET /incidents`, `/incidents/{id}` | Report and timeline |
| `GET /incidents/{id}/postmortem` | Blameless post-mortem draft: timeline, findings and remediation pre-filled, impact and action items left for people |
| `GET /metrics` | The bot's own health: triages by diagnosis, remediations, evidence errors per source, time to report |

Wire it into Alertmanager with `deploy/alertmanager-receiver.yaml`. `continue: true` keeps paging humans too, because the bot assists on-call and doesn't replace it.
