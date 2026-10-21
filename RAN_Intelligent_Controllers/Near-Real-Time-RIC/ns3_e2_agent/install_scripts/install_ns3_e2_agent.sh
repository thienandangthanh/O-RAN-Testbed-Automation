#!/bin/bash
# install_ns3_e2_agent.sh: build the ns3-e2-agent Docker image inside NIST's
# e2-interface tree, after NIST's install_e2sim.sh has prepared that tree.
#
#   - asserts e2-interface is at the pinned commit da6f82f2 and that NIST's
#     e2sim patch (e2ap_message_handler.cpp) is in place, i.e. install_e2sim.sh ran;
#   - copies this directory to e2-interface/e2sim/e2sm_examples/ns3_e2_agent;
#   - docker build with NIST's context (e2-interface/e2sim) and registry;
#   - writes ns3_e2_agent/run/image.env (image name and ID) for run_ns3_e2_agents.sh.
#
# Env: E2_INTERFACE_DIR (default <Near-Real-Time-RIC>/e2-interface),
#      NS3_E2_AGENT_TAG (default: Testbed short SHA, "-dirty" if ns3_e2_agent/ has changes),
#      CONTAINER_PULL_REGISTRY (default nexus3.o-ran-sc.org:10002, as install_e2sim.sh),
#      BUILD_TIMEOUT_S (default 3600).
# Non-interactive and idempotent: a re-run rebuilds the same tag.
set -euo pipefail
echo "# Script: $(realpath "$0") $*"

AGENT_DIR=$(cd "$(dirname "$(realpath "$0")")/.." && pwd)
NRT_DIR=$(cd "$AGENT_DIR/.." && pwd)
E2_INTERFACE_DIR=${E2_INTERFACE_DIR:-$NRT_DIR/e2-interface}
PINNED_E2_INTERFACE=da6f82f286cdbb38af1178f82f85877b12c2f85b
REGISTRY=${CONTAINER_PULL_REGISTRY:-nexus3.o-ran-sc.org:10002}
BUILD_TIMEOUT_S=${BUILD_TIMEOUT_S:-3600}

die() { echo "ERROR: $*" >&2; exit 1; }

[ -d "$E2_INTERFACE_DIR/e2sim" ] || die "no e2-interface tree at $E2_INTERFACE_DIR (run NIST's install_e2sim.sh first)"
head=$(git -C "$E2_INTERFACE_DIR" rev-parse HEAD)
[ "$head" = "$PINNED_E2_INTERFACE" ] || die "e2-interface is at $head, expected $PINNED_E2_INTERFACE"
patched="$NRT_DIR/install_patch_files/e2-interface/e2sim/src/messagerouting/e2ap_message_handler.cpp"
cmp -s "$patched" "$E2_INTERFACE_DIR/e2sim/src/messagerouting/e2ap_message_handler.cpp" ||
	die "NIST's e2sim patch is not applied in $E2_INTERFACE_DIR (run install_e2sim.sh first)"

if [ -z "${NS3_E2_AGENT_TAG:-}" ]; then
	NS3_E2_AGENT_TAG=$(git -C "$AGENT_DIR" rev-parse --short=12 HEAD)
	if [ -n "$(git -C "$AGENT_DIR" status --porcelain -- . 2>/dev/null)" ]; then
		NS3_E2_AGENT_TAG="$NS3_E2_AGENT_TAG-dirty"
	fi
fi
IMAGE="ns3-e2-agent:$NS3_E2_AGENT_TAG"

python3 -I "$AGENT_DIR/tests/lint-metric-map.py" "$AGENT_DIR/schema/metric-map.v1.json"

dest="$E2_INTERFACE_DIR/e2sim/e2sm_examples/ns3_e2_agent"
rm -rf "$dest"
mkdir -p "$dest"
tar -C "$AGENT_DIR" --exclude=./run -cf - . | tar -C "$dest" -xf -
echo "Copied the agent to $dest"

echo "Building $IMAGE (timeout ${BUILD_TIMEOUT_S}s)..."
(cd "$E2_INTERFACE_DIR/e2sim" &&
	timeout "$BUILD_TIMEOUT_S" docker build --build-arg CONTAINER_PULL_REGISTRY="$REGISTRY" \
		-f e2sm_examples/ns3_e2_agent/Dockerfile -t "$IMAGE" . </dev/null)
image_id=$(docker image inspect --format '{{.Id}}' "$IMAGE")
map_sha=$(sha256sum "$AGENT_DIR/schema/metric-map.v1.json" | cut -d' ' -f1)

mkdir -p "$AGENT_DIR/run"
cat >"$AGENT_DIR/run/image.env" <<EOF
NS3_E2_AGENT_IMAGE=$IMAGE
NS3_E2_AGENT_IMAGE_ID=$image_id
NS3_E2_AGENT_E2_INTERFACE=$head
NS3_E2_AGENT_METRIC_MAP_SHA256=$map_sha
EOF
echo "Built $IMAGE ($image_id); metric map sha256 $map_sha"
echo "Recorded in $AGENT_DIR/run/image.env"
