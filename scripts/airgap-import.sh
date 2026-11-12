#!/usr/bin/env bash
# Imports an air-gap bundle (scripts/airgap-bundle.sh) inside the isolated network.
#
# Usage: scripts/airgap-import.sh -b BUNDLE -r internal-registry.example/srustiops -k cosign.pub
#   -k  the cosign public key you trust, brought separately from the bundle
# It verifies the checksum signature and every file, loads the images with their
# signatures into the internal registry, verifies each image signature there, and
# prints what to set in the chart. Copy modules/ and providers/ into the PVCs it names.
# Needs: cosign, shasum.
set -euo pipefail
B="" REGISTRY="" PUB=""
while getopts "b:r:k:" o; do
  case $o in b) B=$OPTARG;; r) REGISTRY=$OPTARG;; k) PUB=$OPTARG;; *) exit 2;; esac
done
[[ -n "$B" && -n "$REGISTRY" && -n "$PUB" ]] || { sed -n '2,10p' "$0"; exit 2; }

echo "== verifying the bundle"
cosign verify-blob --key "$PUB" --insecure-ignore-tlog --signature "$B/SHA256SUMS.sig" "$B/SHA256SUMS"
(cd "$B" && shasum -a 256 -c --quiet SHA256SUMS)
cmp -s "$PUB" "$B/cosign.pub" || { echo "the bundle's cosign.pub differs from the key you trust" >&2; exit 1; }

echo "== images"
while read -r target digest; do
  cosign load --dir "$B/images/srustiops-$target" "$REGISTRY/srustiops-$target"
  cosign verify --key "$PUB" --insecure-ignore-tlog "$REGISTRY/srustiops-$target@$digest" >/dev/null
  echo "  srustiops-$target@$digest loaded and verified"
done < "$B/images/DIGESTS"

cat <<EOT

Bundle verified. Next:
  1. Copy $B/modules into a PVC (e.g. srustiops-module-mirror) and $B/providers into another (srustiops-provider-mirror).
  2. Install the chart from $B/chart with:
       image.server=$REGISTRY/srustiops-server  image.runner=$REGISTRY/srustiops-runner
       airgap.moduleMirror.existingClaim=srustiops-module-mirror
       airgap.moduleMirror.publicKey=$(cat "$B/modules.pub")
       airgap.providerMirror.existingClaim=srustiops-provider-mirror
       imageVerification.enabled=true imageVerification.publicKey=<contents of $PUB>
EOT
