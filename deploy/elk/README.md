# OpenConsole logs in Elasticsearch

With `LOG_FORMAT=ecs` (set in `deploy/deployment.yaml`) OpenConsole writes every log line to stdout as one JSON object with [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) names. That includes client-go's own messages. Ingesting it needs **no grok**: the line only has to be decoded as JSON. This folder holds an ingest pipeline that does that, routes the two kinds of record to their own data streams, and the mappings for them.

| Data stream | Contents |
|---|---|
| `logs-openconsole.audit-<namespace>` | Audit events: who did what, on which cluster / namespace / resource, with which result. Message `audit`; `event.dataset: openconsole.audit`. |
| `logs-openconsole.app-<namespace>` | Application logs: HTTP requests, startup, recordings, Kubernetes client errors. `event.dataset: openconsole.app`. |

Field reference: README → [Structured logging](../../README.md#structured-logging-slog).

## Files

| File | What it is |
|---|---|
| `openconsole-logs.pipeline.json` | Ingest pipeline `openconsole-logs`. It runs only on OpenConsole lines (JSON with `"service.name":"openconsole"`); other containers' lines pass through unchanged. Steps:<br>1. A `json` processor decodes the line into the document. It merges with what Elastic Agent added, so `kubernetes.*`, `container.*` and `log.file.path` stay.<br>2. `dot_expander` turns `user.name` into `user: {name}`.<br>3. A script sets `event.dataset` and, for audit events, `event.kind` and `event.outcome` (`success` for `*.success`; `failure` for `*.failed`, `*.denied`, `*.rate_limited`, `*.locked`).<br>4. `reroute` sends the record to `logs-openconsole.audit` or `logs-openconsole.app`. |
| `openconsole@mappings.component-template.json` | Mappings for the fields OpenConsole writes: keywords for names, `client.ip` as `ip`, `event.duration` and `http.response.status_code` as `long`, `openconsole.ts` as `date`, `openconsole.*` (the resource an action ran against) as keywords. |
| `logs-openconsole.index-template.json` | Index template for the two data streams. It combines the stack's `logs@*` / `ecs@mappings` templates with the mappings above. |
| `install.sh` | Installs the three and hooks the pipeline into the Kubernetes integration (below). Safe to re-run. |

Requires Elasticsearch 8.8 or later (`reroute`); tested on 8.15.3.

## Install

```bash
ES_URL=https://elasticsearch.example:9200 ES_API_KEY=<base64 id:key> deploy/elk/install.sh
# or ES_USER=elastic ES_PASSWORD=...; ES_INSECURE=1 for a self-signed certificate
```

```text
ok   PUT /_component_template/openconsole@mappings
ok   PUT /_index_template/logs-openconsole
ok   PUT /_ingest/pipeline/openconsole-logs
ok   PUT /_ingest/pipeline/logs-kubernetes.container_logs@custom
```

The API key needs the `manage_index_templates` and `manage_pipeline` cluster privileges.

### How the pipeline is reached

Elastic Agent's **Kubernetes** integration collects the pod's stdout into `logs-kubernetes.container_logs-*`, and its ingest pipeline calls `logs-kubernetes.container_logs@custom` at the end. `install.sh` creates that `@custom` pipeline with one processor that calls `openconsole-logs`.

If `@custom` **already exists** in your cluster, `install.sh` leaves it alone and prints the processor to add to it instead:

```json
{ "pipeline": { "name": "openconsole-logs", "ignore_missing_pipeline": true } }
```

If the logs arrive through another integration, hook the same processor into that integration's `@custom` pipeline, or set `OC_HOOK_PIPELINE=<its @custom pipeline>` when you run `install.sh`.

Nothing has to change in the Elastic Agent policy.

## Check

After the next request to OpenConsole, open Kibana → Discover with a `logs-openconsole.audit-*` data view, or use Dev Tools:

```text
GET logs-openconsole.audit-*/_search
{ "size": 5, "sort": [{ "@timestamp": "desc" }] }
```

KQL examples (audit):

```text
event.action : "login.failed"
event.outcome : "failure"
user.name : "dev1" and event.outcome : "failure"
event.action : pod.exec.* and openconsole.cluster : "prod-aks"
event.action : "deployment.restart.success" and openconsole.namespace : "payments"
http.request.id : "4rvxiU2EG9Lmx4OB"
```

KQL examples (application, `logs-openconsole.app-*`):

```text
http.response.status_code >= 400
log.level : "error"
url.path : "/api/auth/login"
```

The request id is the same in an audit event and in the `http.request` record that caused it, and in the `X-Request-Id` response header.

A line that looks like OpenConsole JSON but can't be parsed keeps its raw `message`. It gets the tag `openconsole_json_failure` and the reason in `error.message`, and stays in `logs-kubernetes.container_logs-*`.

## Remove

```text
DELETE _ingest/pipeline/logs-kubernetes.container_logs@custom   # only if install.sh created it
DELETE _ingest/pipeline/openconsole-logs
DELETE _index_template/logs-openconsole
DELETE _component_template/openconsole@mappings
```

## Verified

Tested on Elasticsearch 8.15.3 with the image built from this version, using lines captured while it worked against a k3d cluster: sign-ins, user creation, a denied and an allowed restart, a pod shell with exit code 3, then the cluster stopped to produce client-go errors. The lines were sent the way the Kubernetes integration sends them, and:
- `_bulk` reported no errors, and the records landed in their data streams (14 audit, 119 application);
- `@timestamp` is the event time;
- Agent's `kubernetes.*`, `container.*` and `log.file.path` are kept;
- the fields have the types above, and the KQL examples match;
- other containers' lines, plain text or JSON, are not changed;
- a broken line is tagged and stays where it was.

`install.sh` was run twice; the second run changed nothing it shouldn't.
