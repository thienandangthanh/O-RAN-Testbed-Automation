#!/bin/bash
#
# NIST-developed software is provided by NIST as a public service. You may use,
# copy, and distribute copies of the software in any medium, provided that you
# keep intact this entire notice. You may improve, modify, and create derivative
# works of the software or any portion of the software, and you may copy and
# distribute such modifications or works. Modified works should carry a notice
# stating that you changed the software and should note the date and nature of
# any such change. Please explicitly acknowledge the National Institute of
# Standards and Technology as the source of the software.
#
# NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY
# OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW,
# INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST
# NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE
# UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES
# NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR
# THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
# RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
#
# You are solely responsible for determining the appropriateness of using and
# distributing the software and you assume all risks associated with its use,
# including but not limited to the risks and costs of program errors, compliance
# with applicable laws, damage to or loss of data, programs or equipment, and
# the unavailability or interruption of operation. This software is not intended
# to be used in any situation where a failure could cause risk of injury or
# damage to property. The software developed by NIST employees is not subject to
# copyright protection within the United States.

echo "# Script: $(realpath "$0") $@"

# Run this script to build and deploy the Traffic Steering xApp (trafficxapp) in the Near-Real-Time RIC.
# More information can be found at: https://github.com/o-ran-sc/ric-app-ts and https://docs.o-ran-sc.org/projects/o-ran-sc-ric-app-ts/en/latest/user-guide.html
#
# Modified (2026-11): the Testbed patch set listed in install_patch_files/xApps/ts/patches.manifest is applied in
# order, after every file the patches change is restored to the checked-out commit (the one pinned in
# commit_hashes.json). The image is labelled patchset.sha256 (sha256 of patches.manifest followed by each listed
# patch, in manifest order), and is rebuilt whenever that label differs.

# Exit immediately if a command fails
set -e

CURRENT_DIR=$(pwd)
SCRIPT_DIR=$(dirname "$(realpath "$0")")
PARENT_DIR=$(dirname "$SCRIPT_DIR")
cd "$PARENT_DIR"

# Run a sudo command every minute to ensure script execution without user interaction
./install_scripts/start_sudo_refresh.sh
trap './install_scripts/stop_sudo_refresh.sh 2>/dev/null || true' EXIT

if ! kubectl get pods -n ricplt | grep r4-influxdb-influxdb2 &>/dev/null; then
    echo "The InfluxDB pod is not running, installing it..."
    ./install_scripts/install_influxdb_pod.sh
fi

if [ "$CHART_REPO_URL" != "http://0.0.0.0:8090" ]; then
    echo "Registering the Chart Museum URL..."
    ./install_scripts/register_chart_museum_url.sh
    export CHART_REPO_URL="http://0.0.0.0:8090"
fi
sudo ./install_scripts/run_chart_museum.sh

mkdir -p xApps
cd xApps

if [ ! -d "ts" ]; then
    echo "Cloning Traffic Steering xApp (trafficxapp)..."
    ./../install_scripts/git_clone.sh https://gerrit.o-ran-sc.org/r/ric-app/ts.git --https
fi

cd ts

if grep -q "service-ricxapp-ad-rmr:4560" assets/bootstrap.rt; then
    echo "Patching bootstrap.rt to use AD RMR service..."
    if [ ! -f "assets/bootstrap.previous.rt" ]; then
        cp assets/bootstrap.rt assets/bootstrap.previous.rt
    fi
    sed -i 's/service-ricxapp-ad-rmr:4560/service-ricxapp-ad-rmr.ricxapp.svc.cluster.local:4560/g' assets/bootstrap.rt
fi

if [ -f "routes.txt" ] && grep -q "service-ricxapp-ad-rmr:4560" routes.txt; then
    echo "Patching routes.txt to use AD RMR service..."
    if [ ! -f "routes.previous.txt" ]; then
        cp routes.txt routes.previous.txt
    fi
    sed -i 's/service-ricxapp-ad-rmr:4560/service-ricxapp-ad-rmr.ricxapp.svc.cluster.local:4560/g' routes.txt
fi

# The patch set, in manifest order: the Go a1mediator (3.x) sends the A1 policy body as a JSON string under
# "payload", which the TS xApp reads only as an object (the threshold would never be set); rtmgr routes RIC control
# acks (12041/12042) at subid -1 to every xApp, and xapp-frame-cpp 2.3.6 frees an unmatched buffer twice (glibc
# aborts the pod) unless a do-nothing default handler is registered; and the cell map takes keys only from NR nodes
# (en_gnb_/gnb_ meids), read from the hex text of the X2 request part that e2mgr keeps (only NR cells are PSCell
# targets, 3GPP TS 37.340 10.5.1); and the gRPC UeId gains enGNBUEID (field 2), with rc.pb.cc/rc.pb.h regenerated by
# protoc 3.6.1. Restoring first rewrites the sources, so the image below is rebuilt from the
# patched tree.
TS_PATCH_DIR="$PARENT_DIR/install_patch_files/xApps/ts"
mapfile -t TS_PATCHES < <(grep -vE '^\s*(#|$)' "$TS_PATCH_DIR/patches.manifest")
if [ "${#TS_PATCHES[@]}" -eq 0 ]; then
    echo "ERROR: $TS_PATCH_DIR/patches.manifest lists no patch"
    exit 1
fi
TS_PATCHSET_SHA256=$( (cat "$TS_PATCH_DIR/patches.manifest" && for p in "${TS_PATCHES[@]}"; do cat "$TS_PATCH_DIR/$p"; done) | sha256sum | cut -d' ' -f1)
mapfile -t TS_PATCHED_FILES < <(for p in "${TS_PATCHES[@]}"; do git apply --numstat "$TS_PATCH_DIR/$p" | cut -f3; done | sort -u)
for f in "${TS_PATCHED_FILES[@]}"; do
    echo "Restoring $f to $(git rev-parse --short HEAD)..."
    if git cat-file -e "HEAD:$f" 2>/dev/null; then
        git checkout -q HEAD -- "$f"
    else
        rm -f "$f"
    fi
done
for p in "${TS_PATCHES[@]}"; do
    echo "Applying $p..."
    git apply --verbose "$TS_PATCH_DIR/$p"
done
echo "TS_PATCHSET_SHA256=$TS_PATCHSET_SHA256"

echo "Creating and modifying the configuration file xapp-descriptor/config-file_updated.json"
# Check if jq is installed; if not, install it
if ! command -v jq &>/dev/null; then
    echo "Installing jq..."
    sudo apt-get update
    APTVARS="NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive"
    sudo env $APTVARS apt-get install -y jq
fi

FILE="xapp-descriptor/config-file_updated.json"
sudo rm -rf "$FILE"
cp xapp-descriptor/config-file.json "$FILE"
# Modify the required fields using jq and overwrite the original file
jq '.containers[0].image.tag = "latest" |
    .containers[0].image.registry = "127.0.0.1:80" |
    .containers[0].image.name = "trafficxapp"' "$FILE" >tmp.$$.json && mv tmp.$$.json "$FILE"

# Check if docker is accessible from the current user, and if not, repair its permissions
if [ -z "$FIXED_DOCKER_PERMS" ]; then
    if ! OUTPUT=$(docker info 2>&1); then
        if echo "$OUTPUT" | grep -qiE 'permission denied|cannot connect to the docker daemon'; then
            echo "Docker permissions will repair on reboot."
            sudo groupadd -f docker
            if [ -n "$SUDO_USER" ]; then
                sudo usermod -aG docker "${SUDO_USER:-root}"
            else
                sudo usermod -aG docker "${USER:-root}"
            fi
            # Rather than requiring a reboot to apply docker permissions, set the docker group and re-run the parent script
            export FIXED_DOCKER_PERMS=1
            if ! command -v sg &>/dev/null; then
                echo
                echo "WARNING: Could not find set group (sg) command, docker may fail without sudo until the system reboots."
                echo
            else
                exec sg docker -c "$(printf '%q ' "$CURRENT_DIR/$0" "$@")"
            fi
        fi
    fi
fi

TRAFFICXAPP_NEWER_FILE=$([ -f trafficxapp.tar ] && find Dockerfile CMakeLists.txt assets src -type f -newer trafficxapp.tar -print -quit || true)
TRAFFICXAPP_IMAGE_LABEL=$(docker image inspect --format '{{index .Config.Labels "patchset.sha256"}}' 127.0.0.1:80/trafficxapp:latest 2>/dev/null || true)
if [ ! -f trafficxapp.tar ] || [ -n "$TRAFFICXAPP_NEWER_FILE" ] || [ "$TRAFFICXAPP_IMAGE_LABEL" != "$TS_PATCHSET_SHA256" ]; then
    docker build --network host --label "patchset.sha256=$TS_PATCHSET_SHA256" -t 127.0.0.1:80/trafficxapp:latest .
    docker save -o trafficxapp.tar 127.0.0.1:80/trafficxapp:latest
    sudo chmod 755 trafficxapp.tar
    sudo chown "${SUDO_USER:-$USER}" trafficxapp.tar

    # Import the image into the containerd container runtime
    sudo ctr -n=k8s.io image import trafficxapp.tar
else
    echo "Traffic Steering xApp (trafficxapp) is already built with patch set $TS_PATCHSET_SHA256, skipping."
fi

echo "Onboarding the Traffic Steering xApp (trafficxapp)..."
OUTPUT=$(sudo dms_cli onboard ./xapp-descriptor/config-file_updated.json ./xapp-descriptor/schema.json)
echo $OUTPUT
if echo "$OUTPUT" | grep -q '"status": "Created"'; then
    echo "Onboarding successful: status is 'Created'."
else
    echo "Onboarding failed or 'Created' status not found."
    exit 1
fi

echo "Checking if namespace 'ricxapp' exists..."
if ! kubectl get namespace ricxapp &>/dev/null; then
    echo "Namespace 'ricxapp' does not exist. Creating it..."
    kubectl create namespace ricxapp
fi

echo "Uninstalling application 'trafficxapp' if it exists..."
UNINSTALL_OUTPUT=$(dms_cli uninstall trafficxapp ricxapp 2>&1) || true
if echo "$UNINSTALL_OUTPUT" | grep -q 'release: not found\|No Xapp to uninstall' || true; then
    echo "Application trafficxapp not found or already uninstalled."
else
    echo "$UNINSTALL_OUTPUT"
fi

XAPP_VERSION=$(dms_cli get_charts_list | jq -r '.["trafficxapp"][0].version')

echo "Installing application 'trafficxapp'..."
OUTPUT=$(dms_cli install trafficxapp $XAPP_VERSION ricxapp) || echo "Failed to install trafficxapp xApp with dms_cli."
echo "$OUTPUT"
if echo "$OUTPUT" | grep -qE '"?status"?:\s*"?\bOK\b"?'; then
    echo "Application successfully deployed."
else
    echo "Application failed to deploy."
    exit 1
fi

cd "$PARENT_DIR"

# Stop the sudo timeout refresher, it is no longer necessary to run
./install_scripts/stop_sudo_refresh.sh

stty sane || true
echo
echo
echo "################################################################################"
echo "# Successfully installed Traffic Steering xApp (trafficxapp)                   #"
echo "################################################################################"
