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

# Modified (2026-11): builds the E2 Manager from its pinned gerrit source with the
# patch set in install_patch_files/ric-plt/e2mgr/ applied, and imports it into
# containerd. E2 Manager 6.0.6 reads the en-gNB Global E2 Node ID from the E2AP
# v01 field name, so it refuses every en-gNB E2 Setup that e2term 6.0.6 forwards.
#
#   install_e2mgr_patched.sh [--recipe <recipe.yaml>] [--print-image]
#
# The image is 127.0.0.1:80/ric-plt-e2mgr:<release>-nist180-<first 12 hex of the
# patch-set digest>, labelled e2mgr.source.sha (the pinned commit) and
# patchset.sha256. The digest is the sha256 of patches.manifest followed by each
# listed patch file, in manifest order. A build is skipped when containerd already
# holds that image. --recipe points the recipe's e2mgr image at it (yq), for the
# helm install that follows. --print-image prints the image name and exits.

echo "# Script: $(realpath "$0") $@"

set -e

SCRIPT_DIR=$(dirname "$(realpath "$0")")
cd "$(dirname "$SCRIPT_DIR")"

RECIPE_PATH=""
PRINT_ONLY=false
while [ $# -gt 0 ]; do
    case "$1" in
    --recipe) RECIPE_PATH="$2"; shift 2 ;;
    --print-image) PRINT_ONLY=true; shift ;;
    *) echo "ERROR: unknown argument $1"; exit 1 ;;
    esac
done

E2MGR_URL="https://gerrit.o-ran-sc.org/r/ric-plt/e2mgr.git"
E2MGR_RELEASE="6.0.6"
PATCH_DIR="$(pwd)/install_patch_files/ric-plt/e2mgr"
MANIFEST="$PATCH_DIR/patches.manifest"
REGISTRY="127.0.0.1:80"
IMAGE_NAME="ric-plt-e2mgr"

SOURCE_SHA=$(jq -r --arg u "$E2MGR_URL" '.[$u][1] // empty' commit_hashes.json)
if [[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: commit_hashes.json has no 40-hex commit for $E2MGR_URL"
    exit 1
fi
mapfile -t PATCHES < <(grep -vE '^\s*(#|$)' "$MANIFEST")
if [ "${#PATCHES[@]}" -eq 0 ]; then
    echo "ERROR: $MANIFEST lists no patch"
    exit 1
fi
PATCHSET_SHA256=$( (cat "$MANIFEST" && for p in "${PATCHES[@]}"; do cat "$PATCH_DIR/$p"; done) | sha256sum | cut -d' ' -f1)
IMAGE="$REGISTRY/$IMAGE_NAME:$E2MGR_RELEASE-nist180-${PATCHSET_SHA256:0:12}"
if [ "$PRINT_ONLY" = true ]; then
    echo "$IMAGE"
    exit 0
fi

if sudo ctr -n=k8s.io images ls -q | grep -qxF "$IMAGE"; then
    echo "E2 Manager image $IMAGE is already in containerd, skipping the build."
else
    mkdir -p ric-plt
    cd ric-plt
    if [ ! -d e2mgr ]; then
        echo "Cloning the E2 Manager (e2mgr)..."
        ./../install_scripts/git_clone.sh "$E2MGR_URL" --https
    fi
    cd e2mgr
    git fetch -q origin "$SOURCE_SHA" 2>/dev/null || true
    git checkout -q --detach "$SOURCE_SHA"
    git reset -q --hard "$SOURCE_SHA"
    git clean -q -fdx
    for p in "${PATCHES[@]}"; do
        echo "Applying $p..."
        git apply --whitespace=nowarn "$PATCH_DIR/$p"
    done
    cd E2Manager
    # The image build runs build-e2mgr-ubuntu.sh, which runs the patch set's unit tests and fails on a failure.
    docker build --network host --label "e2mgr.source.sha=$SOURCE_SHA" --label "patchset.sha256=$PATCHSET_SHA256" \
        -t "$IMAGE" .
    cd ../../..
    docker save -o ric-plt/e2mgr.tar "$IMAGE"
    sudo ctr -n=k8s.io image import ric-plt/e2mgr.tar
    rm -f ric-plt/e2mgr.tar
    if ! sudo ctr -n=k8s.io images ls -q | grep -qxF "$IMAGE"; then
        echo "ERROR: $IMAGE is not in containerd after the import."
        exit 1
    fi
fi

if [ -n "$RECIPE_PATH" ]; then
    sudo ./install_scripts/ensure_consistent_yq.sh
    yq e -i ".e2mgr.image.registry = \"$REGISTRY\" | .e2mgr.image.name = \"$IMAGE_NAME\" |
        .e2mgr.image.tag = \"${IMAGE##*:}\"" "$RECIPE_PATH"
    echo "E2 Manager image set to $IMAGE in $RECIPE_PATH"
fi
echo "E2MGR_IMAGE=$IMAGE"
