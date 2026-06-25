# Running SeqDEX locally

Requires Go and [`buf`](https://buf.build).

## Proto codegen
```sh
cd proto && buf dep update && buf generate   # -> proto/gen/go
```

## Wallet (Sequentia-adapted Ocean)

Build:
```sh
cd wallet && go build -o ../bin/seqdex-wallet ./cmd/oceand
```

### IMPORTANT: use an Elements-mode chain for local testing
Plain `elementsd -chain=regtest` runs in **Bitcoin serialization mode**
(`g_con_elementsmode=false`): 80-byte PoW headers and Bitcoin-format transactions,
which the go-elements block/tx parsers the wallet relies on **cannot decode**. Real
Sequentia (`CSequentiaParams` mainnet, `CTestNetParams`) runs in **Elements mode**, so
for a faithful local node use a custom Elements-mode regtest:

```sh
elementsd -datadir=<dir> -server -daemon \
  -con_elementsmode=1 -signblockscript=51 -validatepegin=0 \
  -bech32_hrp=bcrt -blech32_hrp=bcrt -pubkeyprefix=111 -scriptprefix=196 -blindedprefix=4 \
  -rpcport=19996 -rpcuser=s -rpcpassword=s \
  -fallbackfee=0.0001 -acceptnonstdtxn=1 -txindex=1 -blockfilterindex=1
# create a descriptor wallet, mine ~110 blocks, then read getsidechaininfo.pegged_asset
```
These params match `seqnet.SequentiaRegtest` (bech32/blech32 `bcrt`, base58 111/196,
confidential 4). `-blockfilterindex=1` is required by the elements scanner.

### Run the wallet (node-RPC only, no Esplora)
```sh
OCEAN_NETWORK=sequentia-regtest \
OCEAN_NATIVE_ASSET=<getsidechaininfo.pegged_asset hex> \
OCEAN_NODE_RPC_ADDR=http://s:s@127.0.0.1:19996 \
OCEAN_BLOCKCHAIN_SCANNER_TYPE=elements \
OCEAN_DB_TYPE=badger OCEAN_NO_TLS=true \
OCEAN_DATADIR=<datadir> \
./bin/seqdex-wallet
```
Notes:
- `NODE_RPC_ADDR` must be a full URL with credentials: `http://<user>:<pass>@host:port`
  (the RPC client POSTs to that string directly).
- `NATIVE_ASSET` is required — Sequentia's policy asset is genesis-derived, read it from
  the node (`getsidechaininfo.pegged_asset`), never hardcode.
- Leave `ESPLORA_URL` unset for node-RPC-only block fetching; set it to use an external
  Esplora instead. The elements scanner polls the node tip every ~2s to pick up new blocks.

Verified end-to-end: GenSeed → CreateWallet → Unlock → CreateAccount → DeriveAddresses →
fund the derived `bcrt1…` address from the node → the wallet syncs the UTXO/balance.
