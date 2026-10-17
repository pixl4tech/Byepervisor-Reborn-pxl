#!/usr/bin/env bash
# bootstrap_sdk.sh - install the PS5 payload SDK + LLVM 18 toolchain into sdk/
#
# Idempotent: each component is skipped if already present.
#
#   1. sdk/ps5-payload-sdk  - ps5-payload-dev/sdk v0.44 (release zip)
#   2. sdk/llvm18           - Homebrew llvm@18 18.1.8 bottle (arm64) from ghcr,
#                             install-name patched to /opt/homebrew and
#                             ad-hoc re-signed (required on arm64 macOS,
#                             otherwise dyld hangs on load)
#
# Usage:
#   scripts/bootstrap_sdk.sh
#   export PS5_PAYLOAD_SDK=$PWD/sdk/ps5-payload-sdk
#   export LLVM_CONFIG=$PWD/sdk/llvm18/llvm@18/18.1.8/bin/llvm-config
#   make
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="$REPO_ROOT/sdk"
SDK_ZIP_URL="https://github.com/ps5-payload-dev/sdk/releases/download/v0.44/ps5-payload-sdk.zip"
LLVM_VERSION="18.1.8"
# Current rebuild (3) ships arm64_sequoia (no sonoma bottle in rebuild 3).
# Target: arm64 Macs with Homebrew at /opt/homebrew (local + CI macos-15).
# Pinned blob sha256 for integrity.
BOTTLE_TAG="18.1.8-3"
BOTTLE_SHA256="196f7ed71ae73b3b857908c1cdc482048e13feffe4698c69ae807f35ecfd7575"
LLVM_TREE="$SDK_DIR/llvm18/llvm@18/$LLVM_VERSION"
BREW_PREFIX="/opt/homebrew"

log() { echo "[bootstrap] $*"; }

# ------------------------------------------------------ runtime deps -------
# libLLVM/lld link /opt/homebrew/opt/zstd/lib/libzstd.1.dylib; fresh CI
# runners do not have it.
if [ ! -e "$BREW_PREFIX/opt/zstd/lib/libzstd.1.dylib" ]; then
  if command -v brew >/dev/null 2>&1; then
    log "installing zstd via brew ..."
    brew install zstd
  else
    echo "WARNING: zstd not found and brew unavailable" >&2
  fi
fi

# ---------------------------------------------------------------- SDK ------
if [ -f "$SDK_DIR/ps5-payload-sdk/toolchain/prospero.mk" ]; then
  log "ps5-payload-sdk present, skipping"
else
  log "downloading ps5-payload-sdk v0.44 ..."
  mkdir -p "$SDK_DIR"
  curl -fL --retry 3 -o /tmp/ps5-payload-sdk.zip "$SDK_ZIP_URL"
  unzip -q -o /tmp/ps5-payload-sdk.zip -d "$SDK_DIR"
  rm -f /tmp/ps5-payload-sdk.zip
  [ -f "$SDK_DIR/ps5-payload-sdk/toolchain/prospero.mk" ] || {
    echo "ERROR: SDK extracted but prospero.mk not found" >&2; exit 1; }
  log "ps5-payload-sdk installed"
fi

# ---------------------------------------------------------------- LLVM -----
if [ -x "$LLVM_TREE/bin/clang" ]; then
  log "llvm@18 $LLVM_VERSION present, skipping"
else
  log "fetching llvm@18 $LLVM_VERSION bottle (arm64) from ghcr from ghcr ..."
  log "bottle tag: $BOTTLE_TAG"

  TOKEN="$(curl -fsSL 'https://ghcr.io/token?scope=repository:homebrew/core/llvm/18:pull' \
          | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')"
  # 1) index manifest -> arm64 (macOS 15) sub-manifest digest
  DIGEST="$(curl -fsSL -H "Authorization: Bearer $TOKEN" \
           -H 'Accept: application/vnd.oci.image.index.v1+json' \
           "https://ghcr.io/v2/homebrew/core/llvm/18/manifests/$BOTTLE_TAG" \
      | python3 -c '
import sys, json
idx = json.load(sys.stdin)
for m in idx["manifests"]:
    p = m.get("platform", {})
    ver = str(p.get("os.version", ""))
    if (p.get("architecture") == "arm64"
            and p.get("os") == "darwin"
            and ver.startswith("macOS 15")):
        print(m["digest"]); break')"
  # 2) sub-manifest -> bottle layer blob URL (curl: system CA store)
  MANIFEST="$(curl -fsSL -H "Authorization: Bearer $TOKEN" \
           -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
           "https://ghcr.io/v2/homebrew/core/llvm/18/manifests/$DIGEST")"
  BOTTLE_URL="$(echo "$MANIFEST" | python3 -c '
import sys, json
man = json.load(sys.stdin)
layer = man["layers"][0]
print("https://ghcr.io/v2/homebrew/core/llvm/18/blobs/" + layer["digest"])')"
  if [ -z "${BOTTLE_URL:-}" ] || [ "$BOTTLE_URL" = "None" ]; then
    echo "ERROR: could not resolve the bottle URL (tag $BOTTLE_TAG)" >&2
    echo "       install with: brew install llvm@18  (if a bottle exists)" >&2
    exit 1
  fi
  log "downloading bottle: $BOTTLE_URL"
  curl -fL --retry 3 -H "Authorization: Bearer $TOKEN" \
      -o /tmp/llvm18.bottle.tar.gz "$BOTTLE_URL"
  echo "$BOTTLE_SHA256  /tmp/llvm18.bottle.tar.gz" | shasum -a 256 -c -
  mkdir -p "$SDK_DIR/llvm18"
  tar -xzf /tmp/llvm18.bottle.tar.gz -C "$SDK_DIR/llvm18"
  rm -f /tmp/llvm18.bottle.tar.gz

  log "patching install names (@@HOMEBREW_PREFIX@@ -> $BREW_PREFIX) ..."
  PATCHED=()
  while IFS= read -r f; do
    otool -L "$f" 2>/dev/null | awk 'NR>1 {print $1}' |
      grep -F '@@HOMEBREW_PREFIX@@' | while IFS= read -r old; do
        new="${old/\@\@HOMEBREW_PREFIX\@@/$BREW_PREFIX}"
        install_name_tool -change "$old" "$new" "$f" 2>/dev/null || true
      done
    if otool -L "$f" 2>/dev/null | sed -n '2p' | grep -qF '@@HOMEBREW_PREFIX@@'; then
      id="$(otool -L "$f" | sed -n '2p' | awk '{print $1}')"
      newid="${id/\@\@HOMEBREW_PREFIX\@@/$BREW_PREFIX}"
      install_name_tool -id "$newid" "$f" 2>/dev/null || true
    fi
    PATCHED+=("$f")
  done < <(find "$LLVM_TREE/bin" "$LLVM_TREE/lib" -type f 2>/dev/null |
             while IFS= read -r f; do
               # raw-byte scan: BSD strings does not walk the load-command
               # region where install names live
               if LC_ALL=C grep -qaF '@@HOMEBREW_PREFIX@@' "$f" 2>/dev/null; then
                 echo "$f"; fi; done)

  log "ad-hoc re-signing ${#PATCHED[@]} patched files (arm64 code signature) ..."
  if [ ${#PATCHED[@]} -gt 0 ]; then
    for f in "${PATCHED[@]}"; do
      codesign -s - -f "$f" 2>/dev/null || true
    done
  fi

  if [ -d "$BREW_PREFIX/opt" ]; then
    ln -sfn "$LLVM_TREE" "$BREW_PREFIX/opt/llvm@18"
    log "symlink $BREW_PREFIX/opt/llvm@18 -> $LLVM_TREE"
  else
    log "WARNING: $BREW_PREFIX/opt not found; set LLVM_CONFIG manually"
  fi
  log "llvm@18 installed"
fi

log "done. Build with:"
log "  export PS5_PAYLOAD_SDK=$SDK_DIR/ps5-payload-sdk"
log "  export LLVM_CONFIG=$LLVM_TREE/bin/llvm-config"
log "  make"
