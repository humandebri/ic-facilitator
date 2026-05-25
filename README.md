# IC JPYC x402 Facilitator

ICP canister 自体が JPYC on Polygon の x402 v2 `exact` / Permit2 facilitator として動く実装。

## API

- `GET /health`: facilitator の health と EVM address。
- `GET /supported`: x402 v2 `exact`、`eip155:137`、Permit2 support。
- `POST /verify`: x402 `VerifyRequest` を検証する。
- `POST /settle`: x402 `SettleRequest` を検証し、Polygon settlement tx を送信する。

`/settle` は x402 exact Permit2 proxy `0x402085c248EeA27D92E8b30b2C58ed07f9E20001` の `settle(...)` を呼ぶ。facilitator tx の gas は `FACILITATOR_EVM_PRIVATE_KEY` の address が払う。

## 環境変数

```bash
FACILITATOR_EVM_PRIVATE_KEY=0x...
JPYC_POLYGON_ADDRESS=0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB
POLYGON_RPC_SERVICES=https://polygon-bor-rpc.publicnode.com
FACILITATOR_MAX_GAS=500000
SETTLE_CONFIRMATION_TIMEOUT_SECONDS=60
SETTLEMENT_CACHE_TTL_SECONDS=86400
```

`FACILITATOR_EVM_PRIVATE_KEY` は canister env に保存する。v1 の簡易運用前提で、漏洩リスクは受容済みとして扱う。
`POLYGON_RPC_SERVICES` は EVM RPC canister の `RpcServices::Custom` と `canhttp` direct broadcast に使う単一 HTTPS RPC URL。

## Local

```bash
npm install
cargo test -p jpyc_x402_facilitator
npm run build:facilitator
icp network start -d
npm run ic:deploy:local
npm run ic:env:local
npm run smoke:canister
```

`npm run ic:env:local` は `.env` を読み、facilitator 秘密鍵、JPYC address、Polygon RPC URL、gas/settlement 設定を canister の stable env に注入する。

## 実決済 smoke

1. facilitator address に Polygon native gas を入れる。
2. buyer に JPYC を入れる。
3. buyer から JPYC token の Permit2 allowance を付与する。
4. x402 client が `/verify`、`/settle` を呼ぶ。
5. settlement receipt の宛先、JPYC Transfer recipient、amount を検証する。

現行 v1 は JPYC Polygon mainnet の `exact` + Permit2 のみ対応。EIP-3009、Base、Solana、upto、batch settlement は対象外。

## 検証

```bash
cargo test -p jpyc_x402_facilitator
npm test
npm run build
```

`npm run build` は TS typecheck と Rust facilitator build を実行する。TS は canister 運用補助と smoke 用で、facilitator 本体は Rust canister のみ。
