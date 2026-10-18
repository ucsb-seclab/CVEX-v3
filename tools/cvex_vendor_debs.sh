#!/bin/sh
# cvex_vendor_debs.sh <base-image@sha256:...> <outdir> <pkg> [pkg ...]
#
# Vendor the Debian/Ubuntu packages an image needs, so that its Dockerfile can
# install them OFFLINE (docker build --network=none):
#   - resolves <pkg>... (plus every dependency missing from the pinned base image)
#     with apt inside that exact base image, and downloads the .deb files;
#   - writes <outdir>/SHA256SUMS and <outdir>/debs.lock (package=version, one per line).
#
# Install in the Dockerfile with:
#   COPY vendor/debs/ /tmp/debs/
#   RUN cd /tmp/debs && sha256sum -c --quiet SHA256SUMS && dpkg -i *.deb && rm -rf /tmp/debs
set -eu
[ $# -ge 3 ] || { echo "usage: $0 <image@sha256:...> <outdir> <pkg>..." >&2; exit 2; }
img=$1; out=$2; shift 2
case "$img" in *@sha256:*) ;; *) echo "base image must be pinned by @sha256 digest" >&2; exit 2;; esac
mkdir -p "$out"
rm -f "$out"/*.deb "$out"/SHA256SUMS "$out"/debs.lock
docker run --rm --network=bridge -u 0 -v "$(realpath "$out")":/out "$img" sh -c "
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends --download-only $* >/dev/null
  cp /var/cache/apt/archives/*.deb /out/
  chown -R $(id -u):$(id -g) /out"
cd "$out"
sha256sum *.deb > SHA256SUMS
for f in *.deb; do dpkg-deb -f "$f" Package Version | paste -sd= ; done | sort > debs.lock
echo "vendored $(ls *.deb | wc -l) packages ($(du -sh . | cut -f1)) into $out"
