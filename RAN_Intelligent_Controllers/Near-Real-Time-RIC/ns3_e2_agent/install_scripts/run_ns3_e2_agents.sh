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
# Identity (plan R-3): a gnb registers as an en-gNB (gNB ID = id, meid
# en_gnb_<mcc>_<mnc>_%08x), an enb as a macro eNB (macro eNB ID = id, meid
# enB_macro_<mcc>_<mnc>_%06x). Each agent gets E2_X2_PEERS, its X2 neighbours
# (one X2 E2 node component each): a gnb's is its EN-DC master eNB (every enb of
# --nodes, or --x2-master when --nodes has none), an enb's is every gnb of --nodes.
#
# Options: --image (default NS3_E2_AGENT_IMAGE from run/image.env),
#          --env KEY=VAL (extra agent env, repeatable; e.g. E2_SCTP_SRC_PORT=36422),
#          --plmn DIGITS (default 00101; also sets E2_PLMN),
#          --x2-master ID (default 1: the LTE eNB cellId of ns-O-RAN's EN-DC
#          scenarios, the master of every mmWave gNB).
# Env: E2_INDICATION_PERIOD_MS, when set, is passed to every agent: it must equal
#      ns-3's --indicationPeriodicity (in ms) or the agent rejects ns-3's hello;
#      unset, the agent's default (100 ms) applies.
set -euo pipefail
echo "# Script: $(realpath "$0") $*"

AGENT_DIR=$(cd "$(dirname "$(realpath "$0")")/.." && pwd)
RUN_DIR="$AGENT_DIR/run"
die() { echo "ERROR: $*" >&2; exit 1; }

NODES="" IMAGE="" PLMN=00101 X2_MASTER=1
EXTRA_ENV=()
while [ $# -gt 0 ]; do
	case "$1" in
	--nodes) NODES=${2:-}; shift 2 ;;
	--image) IMAGE=${2:-}; shift 2 ;;
	--env) EXTRA_ENV+=(-e "${2:-}"); shift 2 ;;
	--plmn) PLMN=${2:-}; shift 2 ;;
	--x2-master) X2_MASTER=${2:-}; shift 2 ;;
	*) die "unknown argument $1" ;;
	esac
done
[ -n "$NODES" ] || die "--nodes is required (e.g. --nodes gnb:2)"
PERIOD_ENV=()
if [ -n "${E2_INDICATION_PERIOD_MS+x}" ]; then
	PERIOD_ENV=(-e "E2_INDICATION_PERIOD_MS=$E2_INDICATION_PERIOD_MS")
	echo "E2_INDICATION_PERIOD_MS=$E2_INDICATION_PERIOD_MS passed to the agents"
fi
if [ -z "$IMAGE" ] && [ -f "$RUN_DIR/image.env" ]; then
	IMAGE=$(sed -n 's/^NS3_E2_AGENT_IMAGE=//p' "$RUN_DIR/image.env")
fi
[ -n "$IMAGE" ] || die "no --image and no $RUN_DIR/image.env (run install_ns3_e2_agent.sh)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found"
[[ "$PLMN" =~ ^[0-9]{5,6}$ ]] || die "--plmn must be 5 or 6 digits"
[[ "$X2_MASTER" =~ ^[0-9]+$ ]] && [ "$X2_MASTER" -ge 1 ] && [ "$X2_MASTER" -le 65535 ] || die "--x2-master must be 1..65535"

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
# X2 neighbours per kind (see the header).
enbs=() gnbs=()
for p in "${PAIRS[@]}"; do
	if [ "${p%%:*}" = enb ]; then enbs+=("${p##*:}"); else gnbs+=("${p##*:}"); fi
done
GNB_PEERS=$(IFS=','; echo "${enbs[*]:-$X2_MASTER}")
ENB_PEERS=$(IFS=','; echo "${gnbs[*]:-}")
[ "${#enbs[@]}" -eq 0 ] || [ -n "$ENB_PEERS" ] || die "an enb needs at least one gnb in --nodes (its X2 neighbours)"
entries=()
for p in "${PAIRS[@]}"; do
	kind=${p%%:*} id=${p##*:}
	port=$((38470 + id))
	if [ "$kind" = gnb ]; then peers=$GNB_PEERS; else peers=$ENB_PEERS; fi
	name="ns3-e2-agent-$id"
	cid=$(docker run -d --init --restart always --name "$name" \
		--label ns3e2.agent=1 --label "ns3e2.nodeId=$id" --label "ns3e2.kind=$kind" \
		--log-opt max-size=20m --log-opt max-file=3 \
		-p "127.0.0.1:$port:$port" \
		-e "E2_NODE_ID=$id" -e "E2_NODE_KIND=$kind" -e "E2_PLMN=$PLMN" -e "E2_X2_PEERS=$peers" \
		-e "E2_TERM_ADDR=$E2TERM_IP" -e "E2_TERM_PORT=$E2TERM_PORT" -e "E2_IPC_PORT=$port" \
		"${PERIOD_ENV[@]}" "${EXTRA_ENV[@]}" "$IMAGE" </dev/null)
	# Inventory name e2term builds (BuildRunName.h: translatePlmnId + the ID in hex; plan R-3).
	ran=$(python3 -I -c '
import sys
p, kind, nid = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = [int(c) for c in p]
m3 = d[5] if len(p) == 6 else 15
b = [d[1] << 4 | d[0], m3 << 4 | d[2], d[4] << 4 | d[3]]
mcc = "%d%d%d" % (b[0] & 15, b[0] >> 4, b[1] & 15)
mnc1, mnc2, mnc3 = b[1] >> 4, b[2] & 15, b[2] >> 4
mnc = "%d%d%d" % (mnc1, mnc2, mnc3) if mnc1 != 15 else "0%d%d" % (mnc2, mnc3)
print(("en_gnb_%s_%s_%08x" if kind == "gnb" else "enB_macro_%s_%s_%06x") % (mcc, mnc, nid))' "$PLMN" "$kind" "$id")
	echo "started $name ($kind, X2 neighbours $peers, IPC 127.0.0.1:$port, expected RAN name $ran)"
	entries+=("{\"nodeId\":$id,\"kind\":\"$kind\",\"container\":\"$name\",\"containerId\":\"$cid\",\"ipcPort\":$port,\"e2Term\":\"$E2TERM_IP:$E2TERM_PORT\",\"expectedRanName\":\"$ran\",\"x2Peers\":[$peers],\"image\":\"$IMAGE\",\"imageId\":\"$image_id\"}")
done
{
	printf '{"e2termService":"%s","resolvedAt":"%s","agents":[' "$SVC_NAME" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	(IFS=','; printf '%s' "${entries[*]}")
	printf ']}\n'
} >"$RUN_DIR/agents.json"
python3 -I -m json.tool "$RUN_DIR/agents.json" >/dev/null || die "agents.json is not valid JSON"
echo "Wrote $RUN_DIR/agents.json (${#entries[@]} agents)"
