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

### Elasticsearch 8.7 and older

`install.sh` needs 8.8 for the `reroute` processor. On 8.7 the same files work with three changes. Run them from Kibana → Dev Tools (this setup runs on 8.7.1):

1. **Pipeline without routing.** Install `openconsole-logs.pipeline.json` **without its last processor** (`reroute`). Audit and application records then stay together in the data stream the Agent integration writes the OpenConsole pod's logs to, e.g. `logs-<dataset>-<namespace>`. Tell them apart with `event.dataset : "openconsole.audit"` / `"openconsole.app"`. Call the pipeline from that integration (its `@custom` pipeline or its pipeline setting), as above.
2. **Index template on that data stream.** Install `logs-openconsole.index-template.json` with `index_patterns` set to that data stream (`["logs-<dataset>*"]`) and `priority` above the integration's template. Keep `ignore_missing_component_templates`: 8.7 has no stock `logs@settings` / `ecs@mappings`.
3. **Lifecycle (ILM).** On 8.8+ the stock `logs@settings` gives the data streams the `logs` policy. On 8.7 nothing does: the data stream never rolls over and nothing is deleted (`GET _data_stream/<ds>` shows no `ilm_policy`). Add a policy and attach it:

```text
PUT _ilm/policy/openconsole-audit
{
  "policy": {
    "_meta": { "description": "OpenConsole audit and app logs (kubernetes-openconsole)" },
    "phases": {
      "hot":    { "actions": { "rollover": { "max_age": "30d", "max_primary_shard_size": "10gb" } } },
      "delete": { "min_age": "365d", "actions": { "delete": {} } }
    }
  }
}

PUT _component_template/openconsole@settings
{ "template": { "settings": { "index.lifecycle.name": "openconsole-audit" } } }
```

Add `"openconsole@settings"` at the end of the index template's `composed_of` and `PUT _index_template/logs-openconsole` again (with the full body). New backing indices get the policy from the template; give it to the ones that exist (the data stream name reaches all of them):

```text
PUT <ds>/_settings
{ "index.lifecycle.name": "openconsole-audit" }

GET <ds>/_ilm/explain            ← every index "managed": true; the write index waits in hot / check-rollover-ready
```

The delete age is how long the audit trail stays in Elasticsearch (the database keeps `LOG_RETENTION_DAYS`); set it to what you must keep. Don't create `logs@custom` for this: other `logs-*` templates may use it too.

**After an upgrade that adds fields** (2.22 added ten), `PUT _component_template/openconsole@mappings` with the new file only applies from the next backing index. To get them now, either roll over (`POST <ds>/_rollover`) or add them to the indices that exist: `PUT <ds>/_mapping` with just the new fields under `openconsole.properties`. A field that was already written before its mapping existed got a dynamic type (strings become `text`), which only a rollover fixes; Kibana shows such a field as a conflict until the older index is deleted. Check one with `GET <ds>/_mapping/field/openconsole.verb`.

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

**2.22.0** (API keys, policy, agent API): ten new fields (`openconsole.api_key.id` / `.name`, `admin_scope`, `expires_at`, `api_access`, `by_admin`, `comment`, `mode`, `program`, `recording_id`); the pipeline is unchanged. On an 8.7.1 cluster set up as in *Elasticsearch 8.7 and older*: `PUT <ds>/_mapping` added the ten fields to the live index with the right types; the component template from this version plus a rollover gave the new index every field as mapped here (five fields an older template had left out had been written as `text` before); the ILM policy above reported both backing indices as managed.
