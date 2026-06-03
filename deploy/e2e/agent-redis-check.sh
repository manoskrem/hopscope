#!/usr/bin/env bash
#
# The no-code headline (Phase-5 eBPF agent, Redis-RESP slice): prove that real Redis
# traffic renders on the engine canvas sourced ONLY from the agent's kernel capture —
# with the target NOT cooperating at all. Two halves:
#   A) SEND path — plain SET/GET/DEL render as a Redis node + Topic (tcp_sendmsg capture).
#   B) RECV path — a -WRONGTYPE error reply renders as a Failed edge whose drill-down
#      (/traces + /trace/{id}) carries the Redis ErrorDetails (tcp_recvmsg capture). This is
#      the no-code FAILURE capture: the agent shows not just THAT Redis traffic happened but
#      that a command FAILED and why — with no instrumentation of the target.
#
# This runs against the STANDALONE stack deploy/docker-compose.agent.yml, where:
#   * Redis runs with keyspace notifications OFF, and
#   * the engine has NO Redis provider (no HOPSCOPE_REDIS_URL).
# So any Redis node/edge on /snapshot can ONLY come from the agent's eBPF capture.
# Needs a real Linux kernel with BTF + privileged Docker (the GitHub ubuntu-latest runner).
#
#   docker compose -f deploy/docker-compose.agent.yml up -d --build --wait
#   bash deploy/e2e/agent-redis-check.sh
#
# Exit 0 on success; non-zero with a clear message otherwise.

set -euo pipefail

# ── Config (override via env) ───────────────────────────────────────────────
ENGINE="${HOPSCOPE_ENGINE_URL:-http://localhost:8085}"   # engine REST (host-mapped)
REDIS_CTR="${HOPSCOPE_REDIS_CONTAINER:-hopscope-redis}"   # for docker exec redis-cli
AGENT_CTR="${HOPSCOPE_AGENT_CONTAINER:-hopscope-agent}"   # for logs on failure
DEADLINE="${HOPSCOPE_SNAPSHOT_DEADLINE:-40}"             # seconds to wait for the hop

# ── Tooling preflight ───────────────────────────────────────────────────────
command -v curl   >/dev/null 2>&1 || { echo "FAIL: 'curl' is required." >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "FAIL: 'docker' is required (redis-cli via exec)." >&2; exit 2; }

if command -v jq >/dev/null 2>&1; then
  JSON_TOOL="jq"
elif command -v python3 >/dev/null 2>&1; then
  JSON_TOOL="python3"
else
  echo "FAIL: need 'jq' or 'python3' to read the snapshot (install one)." >&2
  exit 2
fi

redis_cli() { docker exec "$REDIS_CTR" redis-cli "$@"; }

wait_for() {
  # wait_for <description> <url> [curl-extra-args...]
  local desc="$1" url="$2"; shift 2
  local tries=0
  until curl -fsS "$@" "$url" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -ge 60 ]; then
      echo "FAIL: timed out waiting for $desc ($url)." >&2
      exit 1
    fi
    sleep 1
  done
  echo "  ✓ $desc ready"
}

echo "── 1/3  Waiting for engine + Redis ──────────────────────────────────────"
wait_for "engine /healthz" "$ENGINE/healthz"
redis_tries=0
until [ "$(redis_cli ping 2>/dev/null || true)" = "PONG" ]; do
  redis_tries=$((redis_tries + 1))
  if [ "$redis_tries" -ge 60 ]; then
    echo "FAIL: timed out waiting for Redis (docker exec $REDIS_CTR redis-cli ping)." >&2
    exit 1
  fi
  sleep 1
done
echo "  ✓ Redis ready"

echo "── 2/4  Driving plain redis-cli traffic (SET/GET/DEL on user:* and order:*) ──"
# Deliberately NO 'CONFIG SET notify-keyspace-events' — keyevents stay OFF. The engine
# has no Redis provider, so nothing but the agent's kernel capture can observe this.
for i in $(seq 1 20); do
  redis_cli SET "user:$i"  "v$i" >/dev/null
  redis_cli GET "user:$i"        >/dev/null
  redis_cli SET "order:$i" "v$i" >/dev/null
  redis_cli DEL "user:$i"        >/dev/null
done
echo "  ✓ issued commands (the target did NOT cooperate — no keyevents, no provider)"

# Returns 0 if the snapshot on stdin has a brokerType=="Redis" node AND the "user:*"
# Topic node. Those ids are produced only by the agent's RESP→envelope mapping, and no
# Redis provider is configured, so they can ONLY have come from kernel capture.
has_agent_redis() {
  if [ "$JSON_TOOL" = "jq" ]; then
    jq -e '
      ([.nodes[].brokerType] | any(. == "Redis"))
      and ([.nodes[].id] | any(. == "user:*"))
    ' >/dev/null 2>&1
  else
    python3 -c '
import sys, json
d = json.load(sys.stdin)
nodes = d.get("nodes", [])
has_redis = any(n.get("brokerType") == "Redis" for n in nodes)
has_topic = any(n.get("id") == "user:*" for n in nodes)
sys.exit(0 if (has_redis and has_topic) else 1)'
  fi
}

echo "── 3/4  Polling /snapshot up to ${DEADLINE}s for the agent-sourced Redis hop ──"
snapshot=""
ok_send=0
for _ in $(seq 1 "$DEADLINE"); do
  sleep 1
  snapshot="$(curl -fsS "$ENGINE/snapshot" || true)"
  if [ -n "$snapshot" ] && printf '%s' "$snapshot" | has_agent_redis; then
    ok_send=1
    echo "  ✓ /snapshot shows a Redis node + user:* Topic from kernel capture (send path)"
    break
  fi
done
if [ "$ok_send" -ne 1 ]; then
  echo "" >&2
  echo "FAIL: no agent-sourced Redis hop on /snapshot after ${DEADLINE}s." >&2
  echo "Last snapshot nodes were:" >&2
  if [ "$JSON_TOOL" = "jq" ]; then
    printf '%s' "$snapshot" | jq '[.nodes[] | {id, brokerType}]' >&2 || printf '%s\n' "$snapshot" >&2
  else
    printf '%s\n' "$snapshot" >&2
  fi
  echo "── agent logs ──" >&2
  docker logs --tail 50 "$AGENT_CTR" >&2 2>&1 || true
  exit 1
fi

echo "── 4/4  Driving a -WRONGTYPE and asserting a Failed edge + drill-down ──────"
# A list op on a string key is the canonical, timing-free WRONGTYPE producer. redis-cli exits
# non-zero on the error reply, so guard each call (|| true) under `set -e`. Issue a few so a
# single dropped ring-buffer sample doesn't flake the run — the engine dedupes by HopId anyway.
redis_cli SET wrongtype:1 plainstring >/dev/null 2>&1 || true
for _ in $(seq 1 5); do
  redis_cli LPUSH wrongtype:1 x >/dev/null 2>&1 || true
done
echo "  ✓ issued SET wrongtype:1 + LPUSH wrongtype:1 ×5 (each reply is -WRONGTYPE)"

# Returns 0 if the snapshot on stdin has an edge to the "wrongtype:*" Topic with lastStatus==3
# (Failed). With no Redis provider configured, that red edge can ONLY come from the agent's
# kernel recv-error capture correlated back to the LPUSH request.
has_failed_wrongtype_edge() {
  if [ "$JSON_TOOL" = "jq" ]; then
    jq -e '[.edges[] | select(.targetId == "wrongtype:*" and .lastStatus == 3)] | length > 0' >/dev/null 2>&1
  else
    python3 -c '
import sys, json
d = json.load(sys.stdin)
edges = d.get("edges", [])
sys.exit(0 if any(e.get("targetId") == "wrongtype:*" and e.get("lastStatus") == 3 for e in edges) else 1)'
  fi
}

# worstStatus / executionStatus == 3 ⇔ ExecutionStatus.Failed (enums travel as integers).
first_failed_trace_id() {
  if [ "$JSON_TOOL" = "jq" ]; then
    jq -r '[.[] | select(.worstStatus == 3)][0].traceId // empty' 2>/dev/null
  else
    python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for t in d:
    if t.get("worstStatus") == 3:
        print(t.get("traceId", "")); break'
  fi
}

# Returns 0 if the TraceView on stdin has a Failed hop (executionStatus==3) carrying
# ErrorDetails(exceptionType=="WRONGTYPE", non-empty message). Walks roots → children.
trace_has_wrongtype_error() {
  if [ "$JSON_TOOL" = "jq" ]; then
    jq -e '
      [.. | .envelope? // empty] as $envs
      | $envs | any(
          .executionStatus == 3
          and .errorDetails != null
          and .errorDetails.exceptionType == "WRONGTYPE"
          and (.errorDetails.message | type == "string" and length > 0))' >/dev/null 2>&1
  else
    python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
envs = []
def walk(node):
    if isinstance(node, dict):
        if "envelope" in node and isinstance(node["envelope"], dict):
            envs.append(node["envelope"])
        for v in node.values():
            walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)
walk(d)
def is_err(e):
    ed = e.get("errorDetails")
    return (e.get("executionStatus") == 3 and isinstance(ed, dict)
            and ed.get("exceptionType") == "WRONGTYPE"
            and isinstance(ed.get("message"), str) and len(ed.get("message")) > 0)
sys.exit(0 if any(is_err(e) for e in envs) else 1)'
  fi
}

# 4a) the Failed edge on /snapshot.
ok_failed=0
for _ in $(seq 1 "$DEADLINE"); do
  sleep 1
  snapshot="$(curl -fsS "$ENGINE/snapshot" || true)"
  if [ -n "$snapshot" ] && printf '%s' "$snapshot" | has_failed_wrongtype_edge; then
    ok_failed=1
    echo "  ✓ /snapshot shows a Failed edge → wrongtype:* (lastStatus=3) from recv capture"
    break
  fi
done
if [ "$ok_failed" -ne 1 ]; then
  echo "" >&2
  echo "FAIL: no Failed edge to wrongtype:* on /snapshot after ${DEADLINE}s." >&2
  echo "Last snapshot edges were:" >&2
  if [ "$JSON_TOOL" = "jq" ]; then
    printf '%s' "$snapshot" | jq '[.edges[] | {sourceId, targetId, lastStatus}]' >&2 || printf '%s\n' "$snapshot" >&2
  else
    printf '%s\n' "$snapshot" >&2
  fi
  echo "── agent logs ──" >&2
  docker logs --tail 50 "$AGENT_CTR" >&2 2>&1 || true
  exit 1
fi

# 4b) drill down: discover the failed trace for that edge, then assert its ErrorDetails.
trace_id=""
for _ in $(seq 1 "$DEADLINE"); do
  sleep 1
  traces="$(curl -fsS -G "$ENGINE/traces" \
    --data-urlencode "status=failed" --data-urlencode "target=wrongtype:*" || true)"
  [ -n "$traces" ] || continue
  trace_id="$(printf '%s' "$traces" | first_failed_trace_id)"
  [ -n "$trace_id" ] && break
done
if [ -z "$trace_id" ]; then
  echo "" >&2
  echo "FAIL: no failed trace for wrongtype:* in /traces?status=failed after ${DEADLINE}s." >&2
  printf 'Last /traces response was: %s\n' "${traces:-<empty>}" >&2
  exit 1
fi
echo "  ✓ discovered failed trace: $trace_id"

# The traceId embeds colons (and the "*" sentinel); the engine's catch-all {*id} route captures
# it. curl sends it raw — colons and "*" are path-safe.
trace="$(curl -fsS "$ENGINE/trace/$trace_id" || true)"
if [ -n "$trace" ] && printf '%s' "$trace" | trace_has_wrongtype_error; then
  echo ""
  echo "PASS: the agent captured a Redis send hop AND a recv-side -WRONGTYPE failure entirely"
  echo "      from the kernel (Redis provider OFF, keyevents OFF). /snapshot shows the Failed"
  echo "      edge and /trace/$trace_id carries ErrorDetails(exceptionType=WRONGTYPE)."
  echo "      No-code failure capture, end to end. The target did not cooperate."
  exit 0
fi

echo "" >&2
echo "FAIL: /trace/$trace_id did not show a Failed hop with WRONGTYPE ErrorDetails." >&2
echo "Trace response was:" >&2
if [ "$JSON_TOOL" = "jq" ]; then
  printf '%s' "$trace" | jq '.' >&2 || printf '%s\n' "${trace:-<empty>}" >&2
else
  printf '%s\n' "${trace:-<empty>}" >&2
fi
echo "── agent logs ──" >&2
docker logs --tail 50 "$AGENT_CTR" >&2 2>&1 || true
exit 1
