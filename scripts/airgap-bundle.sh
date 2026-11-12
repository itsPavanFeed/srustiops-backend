#!/usr/bin/env bash
# Builds everything an air-gapped tenant needs, on a connected machine:
#
#   images/      server and runner images with their cosign signatures (cosign save)
#   modules/     signed registry module packages      -> SRUSTIOPS_MODULE_MIRROR
#   providers/   pinned OpenTofu providers            -> SRUSTIOPS_PROVIDER_MIRROR
#   chart/       the tenant Helm chart
#   SHA256SUMS, SHA256SUMS.sig
#
# Usage: scripts/airgap-bundle.sh -v 0.2.0 -r registry.example.com/srustiops -k cosign.key -o out/
#   -r  staging registry the images are pushed to and signed in (cosign signs registry images)
#   -k  cosign private key (cosign generate-key-pair); its .pub goes in the chart's imageVerification
# Needs: docker (buildx), cosign, tofu, go. Copy the output across, then run scripts/airgap-import.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(cd .. && pwd)"
VERSION="" REGISTRY="" KEY="" OUT="airgap-bundle" PLATFORMS="linux/amd64,linux/arm64"
while getopts "v:r:k:o:p:" o; do
  case $o in v) VERSION=$OPTARG;; r) REGISTRY=$OPTARG;; k) KEY=$OPTARG;; o) OUT=$OPTARG;; p) PLATFORMS=$OPTARG;; *) exit 2;; esac
done
[[ -n "$VERSION" && -n "$REGISTRY" && -n "$KEY" ]] || { sed -n '2,16p' "$0"; exit 2; }
for t in docker cosign tofu go; do command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }; done
mkdir -p "$OUT"/{images,modules,providers,chart}
CATALOG="$ROOT/srustiops-modules/catalog"

echo "== images"
for target in server runner; do
  ref="$REGISTRY/srustiops-$target:$VERSION"
  docker buildx build --platform "$PLATFORMS" --target "$target" --push -t "$ref" \
    --build-context web="$ROOT/srustiops-web" --build-context catalog="$CATALOG" .
  digest=$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' | tr -d '"')
  cosign sign --yes --key "$KEY" --tlog-upload=false "$REGISTRY/srustiops-$target@$digest"
  cosign save --dir "$OUT/images/srustiops-$target" "$REGISTRY/srustiops-$target@$digest"
  echo "$target $digest" >> "$OUT/images/DIGESTS"
done

echo "== module and provider mirrors"
go build -o "$OUT/srustiops" ./cmd/srustiops
"$OUT/srustiops" modules mirror -catalog "$CATALOG" -out "$OUT/modules" -key "${KEY%.key}-modules.key"
cp "${KEY%.key}-modules.key.pub" "$OUT/modules.pub"
"$OUT/srustiops" providers mirror -catalog "$CATALOG" -out "$OUT/providers" -platforms "$(echo "$PLATFORMS" | tr / _)"
cp -R deploy/helm/srustiops-tenant "$OUT/chart/"
cp "${KEY%.key}.pub" "$OUT/cosign.pub"

echo "== checksums"
(cd "$OUT" && find . -type f ! -name 'SHA256SUMS*' ! -name srustiops -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS)
cosign sign-blob --yes --key "$KEY" --tlog-upload=false --output-signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
rm -f "$OUT/srustiops"
echo "bundle ready in $OUT ($(du -sh "$OUT" | cut -f1)). Carry it across with cosign.pub kept separately as the trust anchor."
