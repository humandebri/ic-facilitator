# IC JPYC x402 Facilitator

ICP canister 自体が JPYC on Polygon の x402 v2 `exact` / EIP-3009 facilitator として動く実装。x402 `batch-settlement` は canister-backed channel storage、`/verify`、onchain `deposit` / `claim` / `settle` / `refund` を扱う。

## API

- `GET /health`: facilitator の health と EVM address。
- `GET /supported`: x402 v2 `exact`、`eip155:137`、EIP-3009 support。batch 設定が有効な時だけ `batch-settlement` も返す。
- `GET /seller-credit?seller=0x...`: seller本人wallet の JPYC x402 決済で seller credit を購入する。
- `POST /settle`: x402 `SettleRequest` を検証し、Polygon settlement tx を送信する。
- `POST /verify`: `batch-settlement` 専用。full batch config が揃う時だけ動く。channel state は更新せず、ICP canister storage 上の mirrored `channelId` / `balance` / `totalClaimed` / `withdrawRequestedAt` / `refundNonce` snapshot を公式 SDK 互換の `extra.*` flat fields と監査用 `extra.channelState` に返す。`exact` は `unsupported_verify_scheme` で拒否する。
- query `settlement(key)`, `settlement_count()`, `active_settlement_count()`, `batch_channel(channel_id)`, `batch_channel_count()`, `batch_channel_storage_writer()`, `batch_channels(limit)`, `batch_deleted_channel(channel_id)`, `batch_deleted_channel_count()`, `batch_deleted_channels(limit)`: settlement / batch channel 監査用。
- update `batch_update_channel(channel_id, expected_revision, update)`: server adapter 用の CAS channel storage API。

`/settle` は JPYC token contract の `transferWithAuthorization(...)` を呼ぶ。facilitator tx の gas は `FACILITATOR_EVM_PRIVATE_KEY` の address が払う。
seller は本人wallet で `/seller-credit?seller=0x...` の x402 決済を行い、`SELLER_CREDIT_TOPUP_AMOUNT` 分の credit を購入する。通常 `/settle` は `paymentRequirements.extra.sellerAuthorization` の EIP-191 署名を検証し、`payTo` seller の承認後に `SELLER_SETTLEMENT_FEE_AMOUNT` を reserve する。送信前失敗時だけ refund する。
tx broadcast 後に receipt が failed になった場合、seller fee は refund しない。facilitator 側の calldata/receipt bug が疑われる場合は canister 修正後に運用補填で処理する。
request body は 64KiB で拒否する。`/settle` は同一 seller 単位の active tx がある場合は `429 settlement_queue_busy` を返す。
pending tx は同一 settlement request の再送で receipt refresh と nonce replacement を起動する。broadcast 済み pending record は TTL だけでは purge しない。active tx は settled/failed になるまで保持する。active tx、nonce、settlement、seller credit は stable structures に保存し、upgrade 前後で復元する。
settlement tx は EIP-1559 type-2 で署名する。receipt は `status == 1`、必要 confirmation 数、宛先、JPYC `Transfer(from=payer,to=payTo,value=amount)` log まで検証する。
`/settle` の成功/保留/失敗 response は `extra.settlementKey` を含む。

通常 `/settle` の `sellerAuthorization` は次の形にする。署名 message は `signature` を除く固定 ASCII text で、address は canister の正規化後 lower-case 形式に合わせる。

```json
{
  "version": 1,
  "scheme": "eip191",
  "seller": "0x...",
  "payer": "0x...",
  "amount": "1000000000000000000",
  "asset": "0x431d5dff03120afa4bdf332c61a6e1766ef37bdb",
  "network": "eip155:137",
  "resource": "https://merchant.example/order/123",
  "validAfter": "1700000000",
  "validBefore": "1700000060",
  "authorizationNonce": "0x...",
  "expiresAt": "1700000060",
  "signature": "0x..."
}
```

署名 message:

```text
IC_JPYC_X402_SELLER_AUTH_V1
seller=0x...
payer=0x...
amount=1000000000000000000
asset=0x431d5dff03120afa4bdf332c61a6e1766ef37bdb
network=eip155:137
resource=https://merchant.example/order/123
validAfter=1700000000
validBefore=1700000060
authorizationNonce=0x...
expiresAt=1700000060
```

## 環境変数

```bash
FACILITATOR_EVM_PRIVATE_KEY=0x...
ICP_ENVIRONMENT=ic
ICP_CANISTER=edge
JPYC_EIP712_VERSION=1
POLYGON_RPC_SERVICES=https://polygon-rpc.example
POLYGON_RPC_URL=https://polygon-rpc.example
FACILITATOR_PUBLIC_ORIGIN=https://edge.example
X402_BASE_URL=https://edge.example
FACILITATOR_MAX_GAS=500000
FACILITATOR_MAX_SETTLEMENT_FEE_WEI=30000000000000000
SETTLE_CONFIRMATION_TIMEOUT_SECONDS=60
SETTLE_MIN_CONFIRMATIONS=3
SETTLEMENT_CACHE_TTL_SECONDS=86400
SELLER_CREDIT_PAY_TO=0x...
SELLER_CREDIT_TOPUP_AMOUNT=1000000000000000000
SELLER_SETTLEMENT_FEE_AMOUNT=1000000000000000
BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY=0x...
BATCH_SETTLEMENT_CONTRACT=0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003
BATCH_WITHDRAW_DELAY_SECONDS=900
BATCH_SETTLEMENT_FEE_AMOUNT=1000000000000000
BATCH_MIN_CANISTER_CYCLES=1000000000000
BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL=<resource-server-canister-principal>
BATCH_SETTLEMENT_ACTION=deposit
BATCH_SETTLEMENT_TX=0x...
BATCH_CHANNEL_ID=0x...
BATCH_EXPECTED_MIN_BALANCE=1
BATCH_EXPECTED_TOTAL_CLAIMED=1
BATCH_EXPECTED_MIN_REFUND_NONCE=1
BATCH_DEPOSIT_TX=0x...
BATCH_DEPOSIT_CHANNEL_ID=0x...
BATCH_DEPOSIT_AMOUNT=1
BATCH_DEPOSIT_EXPECTED_MIN_BALANCE=1
BATCH_CLAIM_TX=0x...
BATCH_CLAIM_CHANNEL_ID=0x...
BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED=1
BATCH_REFUND_TX=0x...
BATCH_REFUND_CHANNEL_ID=0x...
BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE=1
BATCH_REFUND_EXPECTED_TOTAL_CLAIMED=1
BATCH_SETTLE_TX=0x...
BATCH_SETTLE_RECEIVER=0x...
BATCH_SETTLE_TOKEN=0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB
BATCH_SETTLE_AMOUNT=1
FACILITATOR_DEBUG_COST=0
```

`FACILITATOR_EVM_PRIVATE_KEY` は repo 外の SEV / subnet / deploy 運用基盤で保護する前提。facilitator 実装は tECDSA を使わない。tECDSA 移行、外部 signer 化、鍵保管方式変更はこの repo の責務ではない。
JPYC token contract は Polygon mainnet の固定値 `0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB` を使う。canister env の `JPYC_POLYGON_ADDRESS` は読まない。
`POLYGON_RPC_SERVICES` は canister 用で、単一 `https://host[:port]` のみ。`POLYGON_RPC_URL` は Node CLI smoke/preflight/receipt 用で、HTTPS、userinfo なし、fragment なしを必須とし、provider API key 用の path/query は許可する。未設定、HTTP、複数 URL、userinfo、fragment は config error とする。単一 RPC のため、gas 推定、nonce、receipt 判定は provider 偏りの残余リスクを持つ。
`FACILITATOR_PUBLIC_ORIGIN` は payment resource URL の origin。Host / forwarded proto header は信用しない。
`SETTLE_MIN_CONFIRMATIONS` は settlement receipt を success 扱いする最小 confirmation 数。既定値は `3`。
`SELLER_CREDIT_PAY_TO` は seller credit 購入代金の受取先。`SELLER_CREDIT_TOPUP_AMOUNT` と `SELLER_SETTLEMENT_FEE_AMOUNT` は JPYC atomic unit。`FACILITATOR_MAX_SETTLEMENT_FEE_WEI` は `gas_limit * max_fee_per_gas` の送信前 cap。超過時は tx を broadcast せず `gas_too_expensive` を返す。
`BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY`、`BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL`、`BATCH_WITHDRAW_DELAY_SECONDS`、`BATCH_SETTLEMENT_FEE_AMOUNT`、`BATCH_SETTLEMENT_CONTRACT` が有効な時だけ `/supported` に `batch-settlement` を広告し、partial / invalid batch config では base capability だけを返す。batch `/verify` / `/settle` は同じ full config を要求する。`BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` は `FACILITATOR_EVM_PRIVATE_KEY` と別 address を導出する鍵にする。`BATCH_SETTLEMENT_CONTRACT` は pinned `@x402/evm` の公式 `BATCH_SETTLEMENT_ADDRESS` `0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003` だけ許可する。`BATCH_WITHDRAW_DELAY_SECONDS` は x402 公式範囲の 900〜2592000 秒だけ許可する。`BATCH_SETTLEMENT_FEE_AMOUNT` は batch `/settle` の onchain tx fee reserve 用。`BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL` は resource server が使う非system canister actor principal で、batch 有効化時は必須。canister の `batch_update_channel` は per-channel CAS、channel id/config/signature 検証、storage 上限、初期create時の会計ゼロ状態、`chargedCumulativeAmount` / `signedMaxClaimable` / `totalClaimed` / `refundNonce` の単調増加を強制し、`chargedCumulativeAmount` 増加は live `pendingRequest` 消費時だけ許可する。公式 `BatchSettlementChannelManager.refundChannel()` の成功後cleanupと同じ channel delete を許可し、削除直前の最終snapshotは上限付きの `batch_deleted_channel*` 監査APIに残す。batch `/settle` は deposit / claim / settle / refund の x402 公式 ABI calldata を送信する。deposit / refund は client-signed payment なので full batch `extra` と EIP-712 version を検証する。claim / settle は公式 `BatchSettlementChannelManager` が `extra: {}` の最小 requirements で送るため、`amount == "0"`、`payTo` / `asset` / channel config / voucher signature / receiverAuthorizer 一致を検証して受理する。tx 送信前に channel / receiver / ERC-20 balance を `eth_call` で検証し、receipt は tx status、confirmations、contract address に加え、settle は `Settled` event、deposit / claim / refund は channel post-state を検証する。

## Cost 計測

`FACILITATOR_DEBUG_COST=1` の時だけ、`/settle`、payment 付き `/seller-credit` に `?debugCost=1` または `x-debug-cost: 1` を付けると、通常レスポンスを `result` に入れ、`cost` を追加する。永続記録は作らない。

```json
{
  "result": {},
  "cost": {
    "totalInstructions": 0,
    "rpcCalls": 6,
    "steps": [{ "name": "settle.pending_nonce", "instructions": 0, "rpcCalls": 1 }]
  }
}
```

`totalInstructions` は canister の call-context instruction counter。native test では 0。`rpcCalls` は固定費算定用の概算で、`pending_nonce=1`、`send_settlement=5`、`gas_too_expensive send_settlement=2`、`refresh=2` として数える。通常 settlement と seller-credit paid settlement の full path は 6 RPC。手順は staging/mainnet で同一 payload を複数回投げ、`settle.send_settlement` まで到達した成功/失敗を集計し、`P95 totalInstructions + RPC 固定費 + 失敗/再送バッファ + 利益` を `SELLER_SETTLEMENT_FEE_AMOUNT` に反映する。mainnet 反映前に `POLYGON_RPC_SERVICES` の RPC が `eth_feeHistory` と `eth_blockNumber` に対応することを確認する。

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
`BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` を指定しない env 注入では、canister 上の `BATCH_*` を空文字で上書きし、過去の batch 設定残留を無効化する。

## 実決済 smoke

1. facilitator address に Polygon native gas を入れる。
2. buyer に JPYC を入れる。
3. seller本人wallet で seller credit をtop-upする。
4. x402 client が EIP-3009 authorization を署名し、`/settle` を呼ぶ。
5. settlement receipt の宛先、JPYC Transfer recipient、amount を検証する。

`X402_PAID_RETRY=1 npm run pay:jpyc` は同一 `payment-signature` を再送し、settlement record の冪等性を smoke する。通常の `npm run pay:jpyc` では副作用のある有料 endpoint への再送を行わない。

batch settlement を有効化する前に `npm run preflight:batch` を通す。これは env の receiver authorizer key / facilitator key との鍵分離 / settlement fee / withdraw delay / official batch settlement contract と、read-only RPC で Polygon chainId、JPYC bytecode/name/decimals/`authorizationState`、batch settlement contract bytecode、`channels` / `refundNonce` / `pendingWithdrawals` / `receivers` selector 応答を確認する。`npm run readiness:jpyc -- --with-batch-mainnet-preflight` でも同じ確認を readiness stage として実行できる。

batch tx 送信後は `npm run receipt:batch` を通す。`BATCH_SETTLEMENT_ACTION` は `deposit` / `claim` / `settle` / `refund`。全 action で expected receiver として `BATCH_SETTLE_RECEIVER` を必須にする。`deposit` / `claim` / `refund` は calldata の `ChannelConfig` に含まれる receiverAuthorizer / withdraw delay 証跡として `BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` と `BATCH_WITHDRAW_DELAY_SECONDS` も必須にする。`deposit` は `BATCH_CHANNEL_ID`、`BATCH_DEPOSIT_AMOUNT`、`BATCH_EXPECTED_MIN_BALANCE`、`claim` は `BATCH_CHANNEL_ID` と `BATCH_EXPECTED_TOTAL_CLAIMED`、`refund` は `BATCH_CHANNEL_ID` と `BATCH_EXPECTED_MIN_REFUND_NONCE`、`settle` は `BATCH_SETTLE_TOKEN` も使う。receipt は success、contract address、`FACILITATOR_EVM_PRIVATE_KEY` 由来の tx sender、confirmation、tx input selector、tx calldata、post-state を検証し、`deposit` は calldata amount と post-state balance を検証する。`deposit` / `claim` / `refund` calldata は channelId / receiver / receiverAuthorizer / token / withdrawDelay を検証する。`settle` calldata は receiver/token のみを検証し、receiverAuthorizer / withdraw delay は canister の `/supported` / `/verify` / broadcast 前検証で確認する。voucher の `maxClaimableAmount` と `totalClaimed` の関係は canister の `/verify` と `/settle` broadcast 前検証で確認する。`settle` は `Settled` event の amount、receiver `totalSettled` post-state、`totalClaimed >= totalSettled` も検証する。`settle` が no-op の場合、canister は tx を送らず `transaction: ""`、`amount: "0"` を返し、reserved fee と nonce を戻す。この場合は receipt が存在しないため `receipt:batch` の対象外にし、actual settle tx が発生した証跡だけ `BATCH_SETTLE_AMOUNT` に正の event amount を入れて検証する。`refund` が `multicall(bytes[])` の場合は内包 call に `refundWithSignature` があり、その ChannelConfig が `BATCH_REFUND_CHANNEL_ID` に一致することも検証する。4種のtx hashが揃った後は `npm run receipt:batch:all` で `BATCH_DEPOSIT_*`、`BATCH_CLAIM_*`、`BATCH_REFUND_*`、`BATCH_SETTLE_*` をまとめて検証する。`receipt:batch:all` と `verify:batch` の deposit 証跡では `BATCH_DEPOSIT_AMOUNT`、settle 証跡では正の `BATCH_SETTLE_AMOUNT` も必須。`npm run readiness:jpyc -- --with-batch-settlement-receipt` でも単発receipt確認を readiness stage として実行できる。

本番有効化直前は `npm run verify:batch` を通す。`verify:batch` は `readiness:batch` と同じ検証を実行する。これは `preflight:batch`、`BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL`、local `BATCH_SETTLEMENT_FEE_AMOUNT` の正の integer 検証、`BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` と `FACILITATOR_EVM_PRIVATE_KEY` の鍵分離、実canisterの batch env name、実canisterの storage writer principal 一致、実canisterの receiver authorizer / batch settlement contract / fee と local env の一致、実canisterの `batch_channel_count` / `batch_channel` / `batch_channels` query API と count/list 件数整合、実canisterの `batch_update_channel` 副作用なし probe、実canister module hash と local wasm SHA-256 の一致、controller 2個以上・storage writer が controller でないこと・freezing threshold 90日以上・cycles残高、`/supported` の batch 広告、`/verify` の batch-only route、deposit / claim / settle / refund の4 receipt、wasm SHA-256、`dist/facilitator.did` の追跡/差分、DID の `batch_channel` / `batch_channel_count` / `batch_channel_storage_writer` / `batch_receiver_authorizer` / `batch_settlement_contract` / `batch_settlement_fee_amount` / `batch_channels` / `batch_deleted_channel` / `batch_deleted_channel_count` / `batch_deleted_channels` / `batch_update_channel` をまとめて JSON 出力する。`verify:batch` の実行 identity は `batch_update_channel` を呼べる controller または `BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL` にする。`/supported` は `BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` から導出した address、`BATCH_WITHDRAW_DELAY_SECONDS`、`JPYC_EIP712_VERSION` との一致も検証する。cycles 下限は既定 `1000000000000` で、必要なら `BATCH_MIN_CANISTER_CYCLES` で上げる。`/verify` は exact scheme を `unsupported_verify_scheme` で拒否する negative probe だけを実行する。実canister確認は `ICP_ENVIRONMENT` と `ICP_CANISTER` を使い、既定は `ic` / `edge`。mainnet では `X402_BASE_URL=https://host[:port]` が必須。local canister は `ICP_ENVIRONMENT=local npm run verify:batch` で確認する。env 名の単体確認は `npm run smoke:canister:env -- --with-batch`、HTTP smoke の単体確認は `npm run smoke:canister -- --with-batch` を使う。4 receipt は `BATCH_DEPOSIT_*`、`BATCH_CLAIM_*`、`BATCH_REFUND_*`、`BATCH_SETTLE_*` の prefixed env を使う。batch tx 送信前の確認だけなら `npm run verify:batch:preflight` を使う。`ready: true` でない場合は `nextCommands` を順に潰す。

resource server 側では公式SDKの server scheme に `IcBatchChannelStorage` を渡す。

```ts
import { BatchSettlementEvmScheme } from "@x402/evm/batch-settlement/server";
import { IcBatchChannelStorage } from "./src/icBatchChannelStorage";

const storage = new IcBatchChannelStorage(canisterActor);
const scheme = new BatchSettlementEvmScheme(receiverAddress, {
  receiverAuthorizerSigner,
  withdrawDelay: 900,
  storage
});
```

`IcBatchChannelStorage` は公式 `ChannelStorage` として使えるが、canister への初期 channel create は会計ゼロ状態だけ許可する。初回 payment は `voucher.maxClaimableAmount == PaymentRequirements.amount` の pending reservation として作る。非ゼロ `chargedCumulativeAmount` は既存 canister channel の live `pendingRequest` を消費する更新でだけ反映し、local storage 欠落から非ゼロ state を新規作成しない。

公式 `scheme.createChannelManager(facilitator, "eip155:137")` の `claim()` / `settle()` は最小 `PaymentRequirements.extra = {}` を送る。facilitator は claim/settle では full extra を要求せず、channel payload と signed voucher から整合性を検証する。deposit/refund の verify/settle は full extra を維持する。

現行 v1 は JPYC Polygon mainnet の `exact` + EIP-3009 が本決済対象。batch settlement は verify/storage、onchain tx 送信、送信前 state read、receipt event/post-state 検証まで対応。Base、Solana、upto、tECDSA は対象外。
EIP-3009 のため buyer は token approval 不要。facilitator 単体では merchant order/resource binding を暗号学的に保証しない。merchant は payment requirements 生成時に resource URL や order ID を拘束する。
merchant は nonce 生成時に order ID、resource URL、amount、payer、seller を DB commitment し、`paymentRequirements.extra.sellerAuthorization` に seller 署名済み commitment を入れる。facilitator は seller authorization と payment payload/resource の整合性を検証するが、注文 DB の最終判定は merchant app 側で行う。
支払い後の ticket/credit 付与は merchant app 側の責務。facilitator 本体は settlement record と seller credit のみ保持する。

## Release

本番投入時は main 直 deploy ではなく annotated tag を使う。`v0.1.0` 作成前に `git tag --list` と `git ls-remote --tags origin` で重複を確認し、tag message に目的、主要変更、検証コマンド、wasm hash 記録手順を含める。

## 検証

```bash
cargo test -p jpyc_x402_facilitator
npm test
npm run build
npm run did:generate
npm run did:check
```

`npm run build` は TS typecheck と Rust facilitator build を実行する。TS は canister 運用補助と smoke 用で、facilitator 本体は Rust canister のみ。
