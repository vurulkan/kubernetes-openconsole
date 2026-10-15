# OpenConsole logs in Elasticsearch

With `LOG_FORMAT=ecs` (set in `deploy/deployment.yaml`) OpenConsole writes every log line to stdout as one nested JSON object following the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html), with `event.dataset`, `event.kind` / `category` / `type` / `outcome` already filled in. That includes client-go's own messages. Ingesting it needs **no grok**: the line only has to be decoded as JSON. This folder holds an ingest pipeline that does that, routes the two kinds of record to their own data streams, and the mappings for them.

| Data stream | Contents |
|---|---|
| `logs-openconsole.audit-<namespace>` | Audit events: who did what, on which cluster / namespace / resource, with which result. Message `audit`; `event.dataset: openconsole.audit`. |
| `logs-openconsole.app-<namespace>` | Application logs: HTTP requests, startup, recordings, Kubernetes client errors. `event.dataset: openconsole.app`. |

Field reference: README → [Structured logging](../../README.md#structured-logging-slog).

## Files

| File | What it is |
|---|---|
| `openconsole-logs.pipeline.json` | Ingest pipeline `openconsole-logs`. It runs only on OpenConsole lines (JSON whose `service.name` is `openconsole`); other containers' lines pass through unchanged. Steps:<br>1. A `json` processor decodes the line into the document. It merges with what Elastic Agent added, so `kubernetes.*`, `container.*` and `log.file.path` stay.<br>2. `dot_expander` handles the dotted keys written by 2.16.1, so lines from both versions end up the same during an upgrade.<br>3. A script fills `event.dataset` / `event.kind` / `event.outcome` only where the line lacks them (2.16.1 lines), and gives audit lines from before 2.17 the 2.17 shape: `event.action` without the outcome (`deployment.restart.success` → `deployment.restart`), bare reads with their resource (`list` + `deployments` → `deployment.list`), renamed actions (`login.failed` → `user.login`, `secret.yaml.view` → `secret.view_yaml`, …), plus `openconsole.verb`, `openconsole.outcome` and `event.type`.<br>4. `reroute` sends the record to `logs-openconsole.audit` or `logs-openconsole.app`. |
| `openconsole@mappings.component-template.json` | Mappings for the fields OpenConsole writes: keywords for names, `source.ip` (and `client.ip` from 2.16.1) as `ip`, `event.duration`, `http.response.status_code` and `http.response.body.bytes` as `long`, `openconsole.ts` as `date`, `openconsole.*` (the resource an action ran against) as keywords, and every audit detail with its own type (`restarted_at` / `started_at` as `date`; `replicas_from`, `replicas_to`, `exit_code`, `duration_ms`, `cluster_id`, … as `long`; `dry_run`, `is_admin`, … as `boolean`). A backend test keeps this file and the list of audit details in step. |
| `logs-openconsole.index-template.json` | Index template for the two data streams. It combines the stack's `logs@*` / `ecs@mappings` templates with the mappings above. |
| `install.sh` | Installs the three and hooks the pipeline into the Kubernetes integration (below). Safe to re-run. |

Requires Elasticsearch 8.8 or later (`reroute`); tested on 8.15.3 and 9.1.0. On 9.x the two data streams are created in LogsDB index mode (the stack default for `logs-*-*`), which only lowers storage; fields and queries are the same.

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

### Without install.sh

**Nothing is parsed until these are installed.** OpenConsole's lines still reach Elasticsearch through the Kubernetes integration, but each one stays a single JSON string in `message` in `logs-kubernetes.container_logs-*`. So:
- there are no `user.name`, `event.action` or `http.response.status_code` fields to filter, aggregate or chart on;
- audit and application records are mixed;
- `@timestamp` is when Agent read the line, not when it was written.

If you can't run the script (no shell access to Elasticsearch, only Kibana), send the same requests from **Kibana → Dev Tools**. Paste the content of each file as the body, in this order:

```text
PUT _component_template/openconsole@mappings        ← openconsole@mappings.component-template.json
PUT _index_template/logs-openconsole                ← logs-openconsole.index-template.json
PUT _ingest/pipeline/openconsole-logs               ← openconsole-logs.pipeline.json
GET _ingest/pipeline/logs-kubernetes.container_logs@custom
```

If the last request returns 404, create it:

```json
PUT _ingest/pipeline/logs-kubernetes.container_logs@custom
{
  "description": "Calls openconsole-logs (kubernetes-openconsole deploy/elk).",
  "processors": [
    { "pipeline": { "name": "openconsole-logs", "ignore_missing_pipeline": true } }
  ]
}
```

If it already exists, add that `pipeline` processor to it instead (Stack Management → Ingest Pipelines → edit), so its existing processors stay.

Only lines written after the installation are parsed; earlier lines stay as they arrived.

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
event.action : "user.login" and event.outcome : "failure"
event.outcome : "failure"
user.name : "dev1" and event.outcome : "failure"
event.action : "pod.exec" and openconsole.cluster : "prod-aks"
event.action : "deployment.restart" and event.outcome : "success" and openconsole.namespace : "payments"
openconsole.verb : "list" and openconsole.resource_type : "secret"
openconsole.replicas_to >= 10
http.request.id : "4rvxiU2EG9Lmx4OB"
```

KQL examples (application, `logs-openconsole.app-*`):

```text
event.category : "web" and event.outcome : "failure"
http.response.status_code >= 500
log.level : "error"
url.path : "/api/auth/login" and source.ip : "10.31.0.0/16"
event.duration > 1000000000          (requests slower than 1 s)
```

The same `service.environment`, `log.level`, `event.outcome` and `source.ip` queries work across services that log ECS the same way, e.g. `service.environment : "prod" and event.outcome : "failure"`.

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

Tested on Elasticsearch 8.15.3 and 9.1.0 with images built from this version (2.16.2) and from 2.16.1, using lines captured while each worked against a k3d cluster: sign-ins, user creation, a denied and an allowed restart, a pod shell with exit code 3, then the cluster stopped to produce client-go errors. Lines from both versions were sent together, the way the Kubernetes integration sends them, as during an upgrade. Results:
- `_bulk` reported no errors, and every record landed in its data stream;
- the nested 2.16.2 lines and the dotted 2.16.1 lines end up with the same fields (2.16.1 lines get `event.dataset` / `event.outcome` from the pipeline);
- `@timestamp` is the event time, and Agent's `kubernetes.*`, `container.*` and `log.file.path` are kept;
- the fields have the types above (`source.ip` matches CIDR queries), and the KQL examples match;
- other containers' lines are not changed, including a JSON line from another service with `user.name: openconsole`;
- a broken line is tagged and stays where it was.

`install.sh` was run twice; the second run changed nothing it shouldn't.

**2.17.0** (structured audit events): tested on 8.15.3 and 9.1.0 (LogsDB) with audit lines written by the 2.17.0 audit code (list, restart with `restarted_at`, a failed scale with `replicas_from` / `replicas_to` and an error, the end of a pod shell, a failed sign-in) and 2.16.2 / 2.16.1 audit lines (bare `list`, `*.success` / `*.denied`, `pod.exec.end`, `login.failed`, `deployments.apply.success`, `admin.create`), sent together through the pipeline. `_bulk` reported no errors; old and new lines are found by the same queries (`event.action : "deployment.restart"`, `event.action : "user.login"`, `event.outcome : "failure"`); `openconsole.restarted_at` is a `date`, `openconsole.replicas_to` / `cluster_id` / `exit_code` are `long`, and range queries on them work.
