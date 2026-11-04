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

# Run this script to build and deploy the RIC Control xApp (rc) in the Near-Real-Time RIC.
# More information can be found at: https://github.com/o-ran-sc/ric-app-rc and https://docs.o-ran-sc.org/projects/o-ran-sc-ric-app-rc/en/latest/overview.html
#
# Modified (2026-11): rc is reset to the commit pinned in commit_hashes.json and the patch set listed in
# install_patch_files/xApps/rc/patches.manifest is applied in order (the RANParameter-ID bound, the APER NR CGI
# target, and DC PSCell Change control with an en-gNB-UEID). The image is labelled rc.source.sha (the pinned commit) and patchset.sha256 (sha256 of patches.manifest
# followed by each listed patch, in manifest order), and is rebuilt whenever that label differs.

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

if [ ! -d "rc" ]; then
    echo "Cloning RIC Control xApp (rc)..."
    ./../install_scripts/git_clone.sh https://gerrit.o-ran-sc.org/r/ric-app/rc.git --https
fi

cd rc

echo "Creating and modifying the configuration file xapp-descriptor/config_updated.json"
# Check if jq is installed; if not, install it
if ! command -v jq &>/dev/null; then
    echo "Installing jq..."
    sudo apt-get update
    APTVARS="NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive"
    sudo env $APTVARS apt-get install -y jq
fi

RC_URL="https://gerrit.o-ran-sc.org/r/ric-app/rc.git"
RC_PATCH_DIR="$PARENT_DIR/install_patch_files/xApps/rc"
RC_SOURCE_SHA=$(jq -r --arg u "$RC_URL" '.[$u][1] // empty' "$PARENT_DIR/commit_hashes.json")
if [[ ! "$RC_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: commit_hashes.json has no 40-hex commit for $RC_URL"
    exit 1
fi
mapfile -t RC_PATCHES < <(grep -vE '^\s*(#|$)' "$RC_PATCH_DIR/patches.manifest")
if [ "${#RC_PATCHES[@]}" -eq 0 ]; then
    echo "ERROR: $RC_PATCH_DIR/patches.manifest lists no patch"
    exit 1
fi
RC_PATCHSET_SHA256=$( (cat "$RC_PATCH_DIR/patches.manifest" && for p in "${RC_PATCHES[@]}"; do cat "$RC_PATCH_DIR/$p"; done) | sha256sum | cut -d' ' -f1)
git fetch -q origin "$RC_SOURCE_SHA" 2>/dev/null || true
git checkout -q --detach "$RC_SOURCE_SHA"
git reset -q --hard "$RC_SOURCE_SHA"
# A file that a patch adds stays untracked after the reset; it is removed so that a re-run applies the set again.
for p in "${RC_PATCHES[@]}"; do git apply --numstat "$RC_PATCH_DIR/$p" | cut -f3; done | sort -u | while read -r f; do
    git cat-file -e "HEAD:$f" 2>/dev/null || rm -f "$f"
done
for p in "${RC_PATCHES[@]}"; do
    echo "Applying $p..."
    git apply --whitespace=nowarn "$RC_PATCH_DIR/$p"
done

FILE="xapp-descriptor/config_updated.json"
sudo rm -rf "$FILE"
cp xapp-descriptor/config.json "$FILE"
# Modify the required fields using jq and overwrite the original file
jq '.containers[0].image.tag = "latest" |
    .containers[0].image.registry = "127.0.0.1:80" |
    .containers[0].image.name = "rc"' "$FILE" >tmp.$$.json && mv tmp.$$.json "$FILE"

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

RC_IMAGE_LABEL=$(docker image inspect --format '{{index .Config.Labels "patchset.sha256"}}' 127.0.0.1:80/rc:latest 2>/dev/null || true)
if [ ! -f rc.tar ] || [ "$RC_IMAGE_LABEL" != "$RC_PATCHSET_SHA256" ]; then
    docker build --network host --label "rc.source.sha=$RC_SOURCE_SHA" --label "patchset.sha256=$RC_PATCHSET_SHA256" \
        -t 127.0.0.1:80/rc:latest .
    docker save -o rc.tar 127.0.0.1:80/rc:latest
    sudo chmod 755 rc.tar
    sudo chown "${SUDO_USER:-$USER}" rc.tar

    # Import the image into the containerd container runtime
    sudo ctr -n=k8s.io image import rc.tar
else
    echo "RIC Control xApp (rc) is already built with patch set $RC_PATCHSET_SHA256, skipping."
fi

echo "Onboarding the RIC Control xApp (rc)..."
OUTPUT=$(sudo dms_cli onboard ./xapp-descriptor/config_updated.json ./xapp-descriptor/schema.json)
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

echo "Uninstalling application 'rc' if it exists..."
UNINSTALL_OUTPUT=$(dms_cli uninstall rc ricxapp 2>&1) || true
if echo "$UNINSTALL_OUTPUT" | grep -q 'release: not found\|No Xapp to uninstall' || true; then
    echo "Application rc not found or already uninstalled."
else
    echo "$UNINSTALL_OUTPUT"
fi

XAPP_VERSION=$(dms_cli get_charts_list | jq -r '.["rc"][0].version')

echo "Installing application 'rc'..."
OUTPUT=$(dms_cli install rc $XAPP_VERSION ricxapp) || echo "Failed to install rc xApp with dms_cli."
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
echo "# Successfully installed RIC Control xApp (rc)                                 #"
echo "################################################################################"
