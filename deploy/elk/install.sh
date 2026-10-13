#!/usr/bin/env bash
# Installs the OpenConsole log pipeline, mappings and index template into
# Elasticsearch (8.8 or later). Safe to re-run. See README.md.
#
#   ES_URL=https://es.example:9200 ES_API_KEY=... deploy/elk/install.sh
#   ES_URL=... ES_USER=elastic ES_PASSWORD=... deploy/elk/install.sh
#
# ES_INSECURE=1 skips TLS verification (self-signed clusters).
# OC_HOOK_PIPELINE overrides the integration pipeline to hook into
# (default: logs-kubernetes.container_logs@custom).
set -euo pipefail

ES_URL=${ES_URL:?set ES_URL, e.g. https://elasticsearch:9200}
HOOK=${OC_HOOK_PIPELINE:-logs-kubernetes.container_logs@custom}
DIR=$(cd "$(dirname "$0")" && pwd)

auth=()
if [ -n "${ES_API_KEY:-}" ]; then auth=(-H "Authorization: ApiKey $ES_API_KEY")
elif [ -n "${ES_USER:-}" ]; then auth=(-u "$ES_USER:${ES_PASSWORD:-}")
fi
tls=()
[ -n "${ES_INSECURE:-}" ] && tls=(-k)

es() { # method path [file]
  local args=(-sS ${tls[@]+"${tls[@]}"} ${auth[@]+"${auth[@]}"} -X "$1" "$ES_URL$2" -H 'Content-Type: application/json')
  [ $# -ge 3 ] && args+=(--data-binary "@$3")
  curl "${args[@]}" -w '\n%{http_code}'
}

put() { # path file
  local out code
  out=$(es PUT "$1" "$2"); code=${out##*$'\n'}
  if [ "$code" -ge 300 ]; then echo "FAIL PUT $1 ($code): ${out%$'\n'*}"; exit 1; fi
  echo "ok   PUT $1"
}

put "/_component_template/openconsole@mappings" "$DIR/openconsole@mappings.component-template.json"
put "/_index_template/logs-openconsole" "$DIR/logs-openconsole.index-template.json"
put "/_ingest/pipeline/openconsole-logs" "$DIR/openconsole-logs.pipeline.json"

# Hook the pipeline into the integration's @custom pipeline, unless one
# already exists: never overwrite someone else's processors.
out=$(es GET "/_ingest/pipeline/$HOOK"); code=${out##*$'\n'}
if [ "$code" = "404" ]; then
  hook=$(mktemp)
  printf '{"description":"Calls openconsole-logs (kubernetes-openconsole deploy/elk).","processors":[{"pipeline":{"name":"openconsole-logs","ignore_missing_pipeline":true}}]}' > "$hook"
  put "/_ingest/pipeline/$HOOK" "$hook"
  rm -f "$hook"
elif grep -q '"openconsole-logs"' <<<"$out"; then
  echo "ok   $HOOK already calls openconsole-logs"
else
  cat <<MSG
NOTE $HOOK already exists and does not call openconsole-logs.
     Add this processor to it (Kibana → Stack Management → Ingest Pipelines):
       { "pipeline": { "name": "openconsole-logs", "ignore_missing_pipeline": true } }
MSG
fi
