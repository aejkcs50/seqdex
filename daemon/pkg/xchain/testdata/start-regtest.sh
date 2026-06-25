#!/usr/bin/env bash
# Bring up a two-chain regtest: a parent "BTC" elements node (anchor source)
# plus an anchored Sequentia node, mirroring
# test/functional/feature_anchor_swap_consistency.py.
set -euo pipefail

REPO="$HOME/SequentiaByClaude"
ELD="$REPO/build-linux/src/elementsd"
ELC="$REPO/build-linux/src/elements-cli"
BASE="${SEQDEX_XCHAIN_DIR:-/tmp/seqdex-xchain-regtest}"

PARENT_DIR="$BASE/parent"
SEQ_DIR="$BASE/seq"
PARENT_RPC=18000
SEQ_RPC=18001
PARENT_P2P=18010
SEQ_P2P=18011

rpc_parent() { "$ELC" -datadir="$PARENT_DIR" -chain=elementsregtest -rpcport=$PARENT_RPC "$@"; }
rpc_seq()    { "$ELC" -datadir="$SEQ_DIR"    -chain=elementsregtest -rpcport=$SEQ_RPC "$@"; }

stop() {
  rpc_parent stop >/dev/null 2>&1 || true
  rpc_seq stop    >/dev/null 2>&1 || true
}

case "${1:-up}" in
stop)
  stop
  exit 0
  ;;
clean)
  stop
  sleep 2
  rm -rf "$BASE"
  exit 0
  ;;
up)
  rm -rf "$BASE"
  mkdir -p "$PARENT_DIR" "$SEQ_DIR"

  COMMON=(-validatepegin=0 -initialfreecoins=0 -con_blocksubsidy=5000000000
          -anyonecanspendaremine=1 -signblockscript=51 -blindedaddresses=0
          -con_default_blinded_addresses=0 -fallbackfee=0.0001 -walletrbf=1
          -txindex=1 -acceptnonstdtxn=1 -con_any_asset_fees=1
          -server -daemon -printtoconsole=0)

  # Parent ("BTC") node
  "$ELD" -datadir="$PARENT_DIR" -chain=elementsregtest \
    -port=$PARENT_P2P -rpcport=$PARENT_RPC "${COMMON[@]}"

  # Wait for parent RPC
  for _ in $(seq 1 60); do rpc_parent getblockcount >/dev/null 2>&1 && break; sleep 0.5; done

  GENESIS="$(rpc_parent getblockhash 0)"

  # cookie auth for the anchored node -> parent mainchain RPC
  COOKIE="$PARENT_DIR/elementsregtest/.cookie"
  for _ in $(seq 1 60); do [ -f "$COOKIE" ] && break; sleep 0.5; done
  RPC_U="$(cut -d: -f1 "$COOKIE")"
  RPC_P="$(cut -d: -f2 "$COOKIE")"

  # Anchored Sequentia node
  "$ELD" -datadir="$SEQ_DIR" -chain=elementsregtest \
    -port=$SEQ_P2P -rpcport=$SEQ_RPC "${COMMON[@]}" \
    -con_bitcoin_anchor=1 -validateanchor=1 -anchorpollinterval=1 \
    -mainchainrpchost=127.0.0.1 -mainchainrpcport=$PARENT_RPC \
    -mainchainrpcuser="$RPC_U" -mainchainrpcpassword="$RPC_P" \
    -parentgenesisblockhash="$GENESIS"

  for _ in $(seq 1 60); do rpc_seq getblockcount >/dev/null 2>&1 && break; sleep 0.5; done

  rpc_parent -named createwallet wallet_name=w descriptors=true >/dev/null
  rpc_seq    -named createwallet wallet_name=w descriptors=true >/dev/null

  echo "PARENT_RPC=$PARENT_RPC"
  echo "SEQ_RPC=$SEQ_RPC"
  echo "PARENT_DIR=$PARENT_DIR"
  echo "SEQ_DIR=$SEQ_DIR"
  echo "GENESIS=$GENESIS"
  echo "up"
  ;;
*)
  echo "usage: $0 [up|stop|clean]" >&2
  exit 2
  ;;
esac
