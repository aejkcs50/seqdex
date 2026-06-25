#!/usr/bin/env bash
# Regenerate the Go bindings for the SeqDEX cross-chain swap API
# (seqdex/v1/xchain.proto, Phase 5 milestone 2) into ../gen/seqdex/v1.
#
# The daemon's main buf.gen.yaml uses LOCAL protoc-gen-go* plugins; this script
# instead uses buf REMOTE plugins pinned to the exact versions the daemon module
# depends on (protobuf v1.30.0 / grpc-go v1.3.0), so no local protoc toolchain
# is required. buf is expected at ~/.local/bin/buf.
#
# Usage:  bash gen-xchain.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # .../protobuf/seqdex
PROTOBUF_DIR="$(cd "$HERE/.." && pwd)"                         # .../protobuf
BUF="${BUF:-$HOME/.local/bin/buf}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/seqdex/v1"
cp "$HERE/v1/xchain.proto" "$WORK/seqdex/v1/xchain.proto"

cat > "$WORK/buf.yaml" <<'YAML'
version: v2
modules:
  - path: .
lint:
  use:
    - STANDARD
  except:
    - PACKAGE_VERSION_SUFFIX
    - ENUM_ZERO_VALUE_SUFFIX
YAML

cat > "$WORK/buf.gen.yaml" <<'YAML'
version: v2
managed:
  enabled: true
  override:
    - file_option: go_package_prefix
      value: github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen
plugins:
  - remote: buf.build/protocolbuffers/go:v1.30.0
    out: gen
    opt: paths=source_relative
  - remote: buf.build/grpc/go:v1.3.0
    out: gen
    opt:
      - paths=source_relative
      - require_unimplemented_servers=false
YAML

( cd "$WORK" && "$BUF" lint && "$BUF" generate )
cp "$WORK/gen/seqdex/v1/xchain.pb.go"      "$PROTOBUF_DIR/gen/seqdex/v1/xchain.pb.go"
cp "$WORK/gen/seqdex/v1/xchain_grpc.pb.go" "$PROTOBUF_DIR/gen/seqdex/v1/xchain_grpc.pb.go"
echo "regenerated $PROTOBUF_DIR/gen/seqdex/v1/{xchain.pb.go,xchain_grpc.pb.go}"
