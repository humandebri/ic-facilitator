# IC JPYC x402 Facilitator

ICP canister 自体が JPYC on Polygon の x402 v2 `exact` / EIP-3009 facilitator として動く実装。

## API

- `GET /health`: facilitator の health と EVM address。
- `GET /supported`: x402 v2 `exact`、`eip155:137`、EIP-3009 support。
- `GET /seller-credit?seller=0x...`: seller本人wallet の JPYC x402 決済で seller credit を購入する。
- `POST /verify`: 非対応。`501 unsupported` を返す。
- `POST /settle`: x402 `SettleRequest` を検証し、Polygon settlement tx を送信する。

`/settle` は JPYC token contract の `transferWithAuthorization(...)` を呼ぶ。facilitator tx の gas は `FACILITATOR_EVM_PRIVATE_KEY` の address が払う。
seller は本人wallet で `/seller-credit?seller=0x...` の x402 決済を行い、`SELLER_CREDIT_TOPUP_AMOUNT` 分の credit を購入する。通常 `/settle` は `payTo` seller の credit から `SELLER_SETTLEMENT_FEE_AMOUNT` を先に reserve し、送信前失敗時だけ refund する。
tx broadcast 後に receipt が failed になった場合、seller fee は refund しない。facilitator 側の calldata/receipt bug が疑われる場合は canister 修正後に運用補填で処理する。
request body は 64KiB で拒否する。`/verify` は body を検証せず `501 {"error":"unsupported","retryable":false}` を返す。`/settle` は同一 settlement を single-flight 化し、facilitator address 単位の active tx がある場合は `429 settlement_queue_busy` を返す。
pending tx は同一 settlement request の再送で receipt refresh と nonce replacement を起動する。別 settlement は active tx が settled/failed になるか、cache TTL で期限切れ purge されるまで `429 settlement_queue_busy` になる。active tx と nonce state は canister upgrade 前後で復元する。
settlement tx は EIP-1559 type-2 で署名する。receipt は `status == 1` だけでなく、宛先と JPYC `Transfer(from=payer,to=payTo,value=amount)` log まで検証する。

## 環境変数

```bash
FACILITATOR_EVM_PRIVATE_KEY=0x...
JPYC_EIP712_VERSION=1
POLYGON_RPC_SERVICES=https://polygon-rpc.example
FACILITATOR_MAX_GAS=500000
FACILITATOR_MAX_SETTLEMENT_FEE_WEI=30000000000000000
SETTLE_CONFIRMATION_TIMEOUT_SECONDS=60
SETTLEMENT_CACHE_TTL_SECONDS=86400
SELLER_CREDIT_PAY_TO=0x...
SELLER_CREDIT_TOPUP_AMOUNT=1000000000000000000
SELLER_SETTLEMENT_FEE_AMOUNT=1000000000000000
```

`FACILITATOR_EVM_PRIVATE_KEY` は SEV サブネット上の canister env に保存する前提。秘密鍵管理は SEV 実行環境と controller 権限管理に依存するため、tECDSA 移行は今回対象外。
JPYC token contract は Polygon mainnet の固定値 `0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB` を使う。canister env の `JPYC_POLYGON_ADDRESS` は読まない。
`POLYGON_RPC_SERVICES` は単一 HTTPS URL のみ。未設定、HTTP、複数 URL は config error とする。単一 RPC のため、gas 推定、nonce、receipt 判定は provider 偏りの残余リスクを持つ。
`SELLER_CREDIT_PAY_TO` は seller credit 購入代金の受取先。`SELLER_CREDIT_TOPUP_AMOUNT` と `SELLER_SETTLEMENT_FEE_AMOUNT` は JPYC atomic unit。`FACILITATOR_MAX_SETTLEMENT_FEE_WEI` は `gas_limit * max_fee_per_gas` の送信前 cap。超過時は tx を broadcast せず `gas_too_expensive` を返す。

## Cost 計測

`/verify`、`/settle`、payment 付き `/seller-credit` に `?debugCost=1` または `x-debug-cost: 1` を付けると、通常レスポンスを `result` に入れ、`cost` を追加する。永続記録は作らない。

```json
{
  "result": {},
  "cost": {
    "totalInstructions": 0,
    "rpcCalls": 5,
    "steps": [{ "name": "settle.pending_nonce", "instructions": 0, "rpcCalls": 1 }]
  }
}
```

`totalInstructions` は canister の call-context instruction counter。native test では 0。`rpcCalls` は固定費算定用の概算で、`verify=0`、`pending_nonce=1`、`send_settlement=4`、`gas_too_expensive send_settlement=2`、`refresh=1` として数える。通常 settlement と seller-credit paid settlement の full path は 5 RPC。手順は staging/mainnet で同一 payload を複数回投げ、`settle.send_settlement` まで到達した成功/失敗を集計し、`P95 totalInstructions + RPC 固定費 + 失敗/再送バッファ + 利益` を `SELLER_SETTLEMENT_FEE_AMOUNT` に反映する。mainnet 反映前に `POLYGON_RPC_SERVICES` の RPC が `eth_feeHistory` に対応することを確認する。

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

`npm run ic:env:local` は `.env` を読み、facilitator 秘密鍵、gas/settlement、seller-credit 設定を canister の stable env に注入する。

## 実決済 smoke

1. facilitator address に Polygon native gas を入れる。
2. buyer に JPYC を入れる。
3. seller本人wallet で seller credit をtop-upする。
4. x402 client が EIP-3009 authorization を署名し、`/settle` を呼ぶ。
5. settlement receipt の宛先、JPYC Transfer recipient、amount を検証する。

`X402_PAID_RETRY=1 npm run pay:jpyc` は同一 `payment-signature` を再送し、settlement record の冪等性を smoke する。通常の `npm run pay:jpyc` では副作用のある有料 endpoint への再送を行わない。

現行 v1 は JPYC Polygon mainnet の `exact` + EIP-3009 のみ対応。Base、Solana、upto、batch settlement は対象外。
EIP-3009 のため buyer は token approval 不要。facilitator 単体では merchant order/resource binding を暗号学的に保証しない。merchant は payment requirements 生成時に resource URL や order ID を拘束する。
支払い後の ticket/credit 付与は merchant app 側の責務。facilitator 本体は settlement record と seller credit のみ保持する。

## 検証

```bash
cargo test -p jpyc_x402_facilitator
npm test
npm run build
```

`npm run build` は TS typecheck と Rust facilitator build を実行する。TS は canister 運用補助と smoke 用で、facilitator 本体は Rust canister のみ。
