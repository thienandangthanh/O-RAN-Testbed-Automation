#!/bin/bash
# run_ns3_e2_agents.sh --nodes <kind:id>[,<kind:id>...] [--image IMG] [--env KEY=VAL]...
#
# Starts one ns3-e2-agent container per E2 node, e.g.
#   --nodes gnb:2                               (P5: one gNB)
#   --nodes enb:1,gnb:2,gnb:3,gnb:4,gnb:5       (scenario-zero default)
# Each container: default bridge (own netns), docker run --init --restart always,
# labels ns3e2.agent=1 / ns3e2.nodeId=<id>, IPC published on 127.0.0.1:(38470+id).
# The agents connect to the single e2term SCTP Service ClusterIP, resolved here
# with kubectl (containers cannot resolve cluster DNS); a ClusterIP survives
# e2term pod deletes. Old agent containers are removed first (idempotent).
# Writes ns3_e2_agent/run/agents.json for the gates.
#
# Options: --image (default NS3_E2_AGENT_IMAGE from run/image.env),
#          --env KEY=VAL (extra agent env, repeatable; e.g. E2_SCTP_SRC_PORT=36422),
#          --plmn DIGITS (default 00101; also sets E2_PLMN).
set -euo pipefail
echo "# Script: $(realpath "$0") $*"

AGENT_DIR=$(cd "$(dirname "$(realpath "$0")")/.." && pwd)
RUN_DIR="$AGENT_DIR/run"
die() { echo "ERROR: $*" >&2; exit 1; }

NODES="" IMAGE="" PLMN=00101
EXTRA_ENV=()
while [ $# -gt 0 ]; do
	case "$1" in
	--nodes) NODES=${2:-}; shift 2 ;;
	--image) IMAGE=${2:-}; shift 2 ;;
	--env) EXTRA_ENV+=(-e "${2:-}"); shift 2 ;;
	--plmn) PLMN=${2:-}; shift 2 ;;
	*) die "unknown argument $1" ;;
	esac
done
[ -n "$NODES" ] || die "--nodes is required (e.g. --nodes gnb:2)"
if [ -z "$IMAGE" ] && [ -f "$RUN_DIR/image.env" ]; then
	IMAGE=$(sed -n 's/^NS3_E2_AGENT_IMAGE=//p' "$RUN_DIR/image.env")
fi
[ -n "$IMAGE" ] || die "no --image and no $RUN_DIR/image.env (run install_ns3_e2_agent.sh)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found"
[[ "$PLMN" =~ ^[0-9]{5,6}$ ]] || die "--plmn must be 5 or 6 digits"

# Validate the node list: kind gnb|enb, id 1..65535, unique ids.
declare -A seen=()
PAIRS=()
IFS=',' read -ra items <<<"$NODES"
for it in "${items[@]}"; do
	[[ "$it" =~ ^(gnb|enb):([0-9]+)$ ]] || die "bad node '$it' (want gnb:<id> or enb:<id>)"
	id=${BASH_REMATCH[2]}
	[ "$id" -ge 1 ] && [ "$id" -le 65535 ] || die "node id $id out of range"
	[ -z "${seen[$id]:-}" ] || die "node id $id given twice"
	seen[$id]=1
	PAIRS+=("${BASH_REMATCH[1]}:$id")
done

# Resolve the e2term SCTP Service: exactly one Service named service-ricplt-e2term-sctp*.
svc_json=$(timeout 60 kubectl get svc -n ricplt -o json </dev/null) || die "kubectl get svc -n ricplt failed"
read -r SVC_NAME E2TERM_IP E2TERM_PORT < <(python3 -I -c '
import json, sys
items = [s for s in json.load(sys.stdin)["items"] if s["metadata"]["name"].startswith("service-ricplt-e2term-sctp")]
if len(items) != 1:
    sys.exit("expected exactly one service-ricplt-e2term-sctp* Service, found %d" % len(items))
s = items[0]
ports = [p["port"] for p in s["spec"].get("ports", []) if p.get("protocol") == "SCTP"]
if len(ports) != 1 or not s["spec"].get("clusterIP"):
    sys.exit("Service %s has no single SCTP port / clusterIP" % s["metadata"]["name"])
print(s["metadata"]["name"], s["spec"]["clusterIP"], ports[0])' <<<"$svc_json") || die "e2term Service resolution failed"
echo "e2term: Service $SVC_NAME -> $E2TERM_IP:$E2TERM_PORT (SCTP)"

"$AGENT_DIR/install_scripts/stop_ns3_e2_agents.sh"

mkdir -p "$RUN_DIR"
image_id=$(docker image inspect --format '{{.Id}}' "$IMAGE")
entries=()
for p in "${PAIRS[@]}"; do
	kind=${p%%:*} id=${p##*:}
	port=$((38470 + id))
	name="ns3-e2-agent-$id"
	cid=$(docker run -d --init --restart always --name "$name" \
		--label ns3e2.agent=1 --label "ns3e2.nodeId=$id" --label "ns3e2.kind=$kind" \
		--log-opt max-size=20m --log-opt max-file=3 \
		-p "127.0.0.1:$port:$port" \
		-e "E2_NODE_ID=$id" -e "E2_NODE_KIND=$kind" -e "E2_PLMN=$PLMN" \
		-e "E2_TERM_ADDR=$E2TERM_IP" -e "E2_TERM_PORT=$E2TERM_PORT" -e "E2_IPC_PORT=$port" \
		"${EXTRA_ENV[@]}" "$IMAGE" </dev/null)
	# Inventory name e2term will build (BuildRunName.h translatePlmnId + gNB-ID hex, 29-bit ID = node id).
	ran=$(python3 -I -c '
import sys
p, gid = sys.argv[1], int(sys.argv[2])
d = [int(c) for c in p]
m3 = d[5] if len(p) == 6 else 15
b = [d[1] << 4 | d[0], m3 << 4 | d[2], d[4] << 4 | d[3]]
mcc = "%d%d%d" % (b[0] & 15, b[0] >> 4, b[1] & 15)
mnc1, mnc2, mnc3 = b[1] >> 4, b[2] & 15, b[2] >> 4
mnc = "%d%d%d" % (mnc1, mnc2, mnc3) if mnc1 != 15 else "0%d%d" % (mnc2, mnc3)
print("gnb_%s_%s_%08x" % (mcc, mnc, gid))' "$PLMN" "$id")
	echo "started $name ($kind, IPC 127.0.0.1:$port, expected RAN name $ran)"
	entries+=("{\"nodeId\":$id,\"kind\":\"$kind\",\"container\":\"$name\",\"containerId\":\"$cid\",\"ipcPort\":$port,\"e2Term\":\"$E2TERM_IP:$E2TERM_PORT\",\"expectedRanName\":\"$ran\",\"image\":\"$IMAGE\",\"imageId\":\"$image_id\"}")
done
{
	printf '{"e2termService":"%s","resolvedAt":"%s","agents":[' "$SVC_NAME" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	(IFS=','; printf '%s' "${entries[*]}")
	printf ']}\n'
} >"$RUN_DIR/agents.json"
python3 -I -m json.tool "$RUN_DIR/agents.json" >/dev/null || die "agents.json is not valid JSON"
echo "Wrote $RUN_DIR/agents.json (${#entries[@]} agents)"
