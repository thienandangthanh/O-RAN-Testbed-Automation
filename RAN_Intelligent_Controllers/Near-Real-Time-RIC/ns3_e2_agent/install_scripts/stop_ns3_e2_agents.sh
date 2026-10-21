#!/bin/bash
# stop_ns3_e2_agents.sh: remove every ns3-e2-agent container (label ns3e2.agent=1).
# docker rm -f also drops the restart policy, so nothing comes back after a
# reboot. Prints each container's last stats line first. Idempotent; verifies
# that no labelled container is left.
set -euo pipefail
echo "# Script: $(realpath "$0") $*"

ids=$(docker ps -aq --filter label=ns3e2.agent=1)
if [ -z "$ids" ]; then
	echo "No ns3-e2-agent containers."
	exit 0
fi
for id in $ids; do
	name=$(docker inspect --format '{{.Name}}' "$id" | sed 's#^/##')
	restarts=$(docker inspect --format '{{.RestartCount}}' "$id")
	last=$(timeout 10 docker logs --tail 200 "$id" 2>/dev/null | grep '^{"event"' | tail -1 || true)
	echo "$name (restarts $restarts) last stats: ${last:-none}"
done
# shellcheck disable=SC2086
timeout 60 docker rm -f $ids >/dev/null
left=$(docker ps -aq --filter label=ns3e2.agent=1)
[ -z "$left" ] || { echo "ERROR: containers still present: $left" >&2; exit 1; }
echo "Removed $(echo "$ids" | wc -w) ns3-e2-agent container(s)."
