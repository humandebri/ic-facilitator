# IC JPYC x402 Facilitator

ICP canister 自体が JPYC on Polygon の x402 v2 `exact` / EIP-3009 facilitator として動く実装。x402 `batch-settlement` は canister-backed channel storage、`/verify`、onchain `deposit` / `claim` / `settle` / `refund` を扱う。

batch settlementにおける資産の所在、署名権限、canister上のミラー情報およびseller creditとの区別は、[Batch settlementの資産管理境界](docs/batch-asset-boundary.md)に記載する。

## API

- `GET /health`: facilitator の health と EVM address。
- `GET /supported`: x402 v2 `exact`、`eip155:137`、EIP-3009 support。batch 設定が有効な時だけ `batch-settlement` も返す。
- `GET /seller-credit?seller=0x...`: seller本人wallet の JPYC x402 決済で seller credit を購入する。
- `POST /settle`: x402 `SettleRequest` を検証し、Polygon settlement tx を送信する。
- `POST /verify`: `batch-settlement` 専用。full batch config が揃う時だけ動く。channel state は更新せず、ICP canister storage 上の mirrored `channelId` / `balance` / `totalClaimed` / `withdrawRequestedAt` / `refundNonce` snapshot を公式 SDK 互換の `extra.*` flat fields と監査用 `extra.channelState` に返す。`exact` は `unsupported_verify_scheme` で拒否する。
- query `settlement(key)`, `seller_settlements(seller, cursor, limit)`, `seller_acceptance(seller)`, `settlement_count()`, `active_settlement_count()`, `batch_channel(channel_id)`, `batch_channel_count()`, `batch_channels(limit)`, `batch_deleted_channel(channel_id)`, `batch_deleted_channel_count()`, `batch_deleted_channels(limit)`, `batch_writer_receiver_scope(writer, receiver)`, `batch_writer_receiver_scope_count()`, `batch_writer_receiver_scopes(limit)`: 認証なし public audit API。
- update `batch_update_channel(channel_id, expected_revision, update)`: server adapter 用の CAS channel storage API。controller は全 receiver、non-controller は SQLite の enabled writer scope がある receiver だけ更新できる。
- update `batch_set_seller(receiver, status)`, `batch_set_writer_receiver_scope(writer, receiver, enabled)`: controller管理API。network profile、token、Batch contract、Exact/Batch料金、3文書versionは`set_runtime_profile(record)`で検証後に一括更新する。

Seller onboardingは`POST /seller-acceptance/challenge`で単回nonce付きEIP-191 messageを取得し、`POST /seller-acceptance`へ署名を返す。challengeは5分有効、sellerごとに最新1件、canister全体で最大1,000件とし、満杯時は期限切れを回収しても空きがなければ429を返す。一時challengeはcanister upgradeで無効化するが、成立済みのseller同意記録は保持する。現行versionへの同意がないsellerはExact・Batch settlementを利用できない。商品、注文、payment intentはmerchant側の責務であり、facilitatorは保持しない。

public audit query は seller / payer / receiver / merchant の突合に使える生データを返す。`BatchChannel` は `channelConfig.payer` / `receiver` / `token` / `receiverAuthorizer`、voucher `signature`、`balance`、`chargedCumulativeAmount`、`pendingRequest`、ms epoch の `lastRequestTimestamp` / `withdrawRequestedAt` / `onchainSyncedAt` を含む。`BatchDeletedChannel` は削除直前の `BatchChannel` 全体、`settlement` は `pay_to` と settlement response / snapshot を返す。署名収集、channel state 推移、payer/receiver/token 相関が可能になる前提で公開する。redaction API や caller 制限は現行 v1 対象外。

`/settle` は JPYC token contract の `transferWithAuthorization(...)` を呼ぶ。facilitator tx の gas は `FACILITATOR_EVM_PRIVATE_KEY` の address が払う。
seller は本人wallet で `/seller-credit?seller=0x...&amount=100` の x402 決済を行い、指定した1〜10,000 JPYC（小数18桁まで）の credit を購入する。通常 `/settle` は `paymentRequirements.extra.sellerAuthorization` の EIP-191 署名を検証し、`payTo` seller の承認後に `SELLER_SETTLEMENT_FEE_AMOUNT` を reserve する。送信前失敗時だけ refund する。
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
POLYGON_RPC_URL=https://polygon-rpc.example
FACILITATOR_PUBLIC_ORIGIN=https://edge.example
X402_BASE_URL=https://edge.example
FACILITATOR_MAX_GAS=500000
FACILITATOR_MAX_SETTLEMENT_FEE_WEI=30000000000000000
SETTLE_CONFIRMATION_TIMEOUT_SECONDS=60
SETTLE_MIN_CONFIRMATIONS=3
SETTLEMENT_CACHE_TTL_SECONDS=86400
SELLER_CREDIT_PAY_TO=0x...
SELLER_SETTLEMENT_FEE_AMOUNT=1000000000000000000
BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY=0x...
BATCH_SETTLEMENT_CONTRACT=0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003
BATCH_WITHDRAW_DELAY_SECONDS=900
BATCH_SETTLEMENT_FEE_AMOUNT=10000000000000000000
BATCH_MIN_CANISTER_CYCLES=1000000000000
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
network、token、BatchSettlement contract、Exact/Batch料金、3文書versionは`set_runtime_profile`で原子的に設定する。`polygon` profileはchain ID 137、本番JPYC、公式BatchSettlement contractとの完全一致を要求する。`amoy` profileはchain ID 80002と、Preview専用の明示的なtest token・contractを要求する。profileの部分変更や両profileのaddress混在は拒否する。
`POLYGON_RPC_URL` は canister と Node CLI で共用し、HTTPS、userinfo なし、fragment なしを必須とする。provider API key 用の path/query は許可する。canister は `canhttp` の非複製HTTPS outcall（`is_replicated=false`）で単一RPCへ直接接続し、EVM RPC canisterは使わない。単一IC replicaと単一RPCを信頼するため、gas推定、nonce、receipt判定には改ざん・provider偏りの残余リスクがある。raw tx hashはローカル計算し、gas/fee cap、receipt transaction hash・送受信者・event・confirmationを検証してfail closedにする。
`FACILITATOR_PUBLIC_ORIGIN` は payment resource URL の origin。Host / forwarded proto header は信用しない。
`SETTLE_MIN_CONFIRMATIONS` は settlement receipt を success 扱いする最小 confirmation 数。既定値は `3`。
`SELLER_CREDIT_PAY_TO` は seller credit 購入代金の受取先。top-up額はリクエストの`amount`でJPYC表示単位として指定し、`SELLER_SETTLEMENT_FEE_AMOUNT`と`BATCH_SETTLEMENT_FEE_AMOUNT`はJPYC atomic unit。料金は通常settle 1 JPYC、全batch action 10 JPYC。`FACILITATOR_MAX_SETTLEMENT_FEE_WEI` は `gas_limit * max_fee_per_gas` の送信前 cap。超過時は tx を broadcast せず `gas_too_expensive` を返す。
`BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY`、`BATCH_WITHDRAW_DELAY_SECONDS`、`BATCH_SETTLEMENT_FEE_AMOUNT`、profileに一致するBatchSettlement contract、active sellerに紐づくenabled writer scopeが1件以上ある時だけ`/supported`に`batch-settlement`を広告する。channel更新はchannel config、payer voucher、receiver authorizer、nonce、累積額、CAS revision、オンチェーン制約で検証し、商品・注文・payment intentには依存しない。`batch_update_channel`は会計値とnonceの単調増加を強制し、削除直前のsnapshotを監査APIに残す。payment-intent APIはbreaking changeとして廃止した。旧SQLiteにintentまたはbindingが残るupgradeはfail-closedとなる。既存mainnet canisterへの直接upgradeは`deploy_mainnet.sh`も拒否するため、旧APIを保持したtransition releaseでlegacy rowを監査・解消してから本releaseへ進む。今回のMVP完了条件にはmainnet移行を含めない。

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

`totalInstructions` は canister の call-context instruction counter。native test では 0。`rpcCalls` は固定費算定用の概算で、`pending_nonce=1`、`send_settlement=5`、`gas_too_expensive send_settlement=2`、`refresh=2` として数える。通常 settlement と seller-credit paid settlement の full path は 6 RPC。batch deposit / claim / refund の runtime tx pathも6 RPC。batch settleはtxありで7 RPC、no-opは1 RPC。staging/mainnetのP95原価を集計し、概ね原価2倍になるよう料金を見直す。mainnet反映前に`POLYGON_RPC_URL`が`eth_feeHistory`と`eth_blockNumber`に対応することを確認する。

`npm run measure:rpc-responses` は `POLYGON_RPC_URL` に読み取り専用RPCを送り、raw JSONのUTF-8 byte数、安全余裕込みの推奨上限、現行20KB比の削減cyclesをJSON出力する。receipt計測には `SETTLEMENT_TX` と `BATCH_DEPOSIT_TX` / `BATCH_CLAIM_TX` / `BATCH_REFUND_TX` / `BATCH_SETTLE_TX` を使い、不足時は終了コード2と `missingReceiptSamples` を返す。秘密鍵やRPC URLは出力しない。

`npm run measure:facilitator-costs` は13-node非複製HTTPS outcallの機能別概算、100件claimの実測gas sample、推奨JPYC料金をJSON出力する。為替・価格・gasは`XDR_USD`、`USD_JPY`、`POL_USD`、`GAS_PRICE_GWEI`で上書きできる。

RPC response size estimate は実測に基づき、block number / gas estimate / nonce は128 bytes、`eth_call` は192 bytes、fee history は320 bytes、raw tx送信は512 bytes、receiptは4KiBとする。receiptはPolygon実測でログ0件相当1,031 bytes、3ログ最大3,258 bytesだった。batch claimはSDK既定の100件を維持し、現行contract ABIではclaim eventをemitしないためclaim件数でreceiptは増えない。未登録のRPC methodは送信前に拒否する。

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
通常のenv同期で`BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY`を省略しても既存batch設定は変更しない。明示的な`--disable-batch`ではreceiver authorizer private keyだけを空文字化し、contract・fee・withdraw delayを有効なruntime profileとして保持したまま、`/supported`のbatch広告とbatch実行をfail-closedで無効化する。

## 実決済 smoke

1. facilitator address に Polygon native gas を入れる。
2. buyer に JPYC を入れる。
3. seller本人wallet で seller credit をtop-upする。
4. x402 client が EIP-3009 authorization を署名し、`/settle` を呼ぶ。
5. settlement receipt の宛先、JPYC Transfer recipient、amount を検証する。

`X402_PAID_RETRY=1 npm run pay:jpyc` は同一 `payment-signature` を再送し、settlement record の冪等性を smoke する。通常の `npm run pay:jpyc` では副作用のある有料 endpoint への再送を行わない。

batch settlement を有効化する前に `npm run preflight:batch` を通す。これは env の receiver authorizer key / facilitator key との鍵分離 / settlement fee / withdraw delay / official batch settlement contract と、read-only RPC で Polygon chainId、JPYC bytecode/name/decimals/`authorizationState`、batch settlement contract bytecode、`channels` / `refundNonce` / `pendingWithdrawals` / `receivers` selector 応答を確認する。`npm run readiness:jpyc -- --with-batch-mainnet-preflight` でも同じ確認を readiness stage として実行できる。

batch tx 送信後は `npm run receipt:batch` を通す。`BATCH_SETTLEMENT_ACTION` は `deposit` / `claim` / `settle` / `refund`。全 action で expected receiver として `BATCH_SETTLE_RECEIVER` を必須にする。`deposit` / `claim` / `refund` は calldata の `ChannelConfig` に含まれる receiverAuthorizer / withdraw delay 証跡として `BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` と `BATCH_WITHDRAW_DELAY_SECONDS` も必須にする。`deposit` は `BATCH_CHANNEL_ID`、`BATCH_DEPOSIT_AMOUNT`、`BATCH_EXPECTED_MIN_BALANCE`、`claim` は `BATCH_CHANNEL_ID` と `BATCH_EXPECTED_TOTAL_CLAIMED`、`refund` は `BATCH_CHANNEL_ID` と `BATCH_EXPECTED_MIN_REFUND_NONCE`、`settle` は `BATCH_SETTLE_TOKEN` も使う。receipt は success、contract address、`FACILITATOR_EVM_PRIVATE_KEY` 由来の tx sender、confirmation、tx input selector、tx calldata、post-state を検証し、`deposit` は calldata amount と post-state balance を検証する。`deposit` / `claim` / `refund` calldata は channelId / receiver / receiverAuthorizer / token / withdrawDelay を検証する。`settle` calldata は receiver/token のみを検証し、receiverAuthorizer / withdraw delay は canister の `/supported` / `/verify` / broadcast 前検証で確認する。voucher の `maxClaimableAmount` と `totalClaimed` の関係は canister の `/verify` と `/settle` broadcast 前検証で確認する。`settle` は `Settled` event の amount、receiver `totalSettled` post-state、`totalClaimed >= totalSettled` も検証する。`settle` が no-op の場合、canister は tx を送らず `transaction: ""`、`amount: "0"` を返し、reserved fee と nonce を戻す。この場合は receipt が存在しないため `receipt:batch` の対象外にし、actual settle tx が発生した証跡だけ `BATCH_SETTLE_AMOUNT` に正の event amount を入れて検証する。`refund` が `multicall(bytes[])` の場合は内包 call に `refundWithSignature` があり、その ChannelConfig が `BATCH_REFUND_CHANNEL_ID` に一致することも検証する。4種のtx hashが揃った後は `npm run receipt:batch:all` で `BATCH_DEPOSIT_*`、`BATCH_CLAIM_*`、`BATCH_REFUND_*`、`BATCH_SETTLE_*` をまとめて検証する。`receipt:batch:all` と `verify:batch` の deposit 証跡では `BATCH_DEPOSIT_AMOUNT`、settle 証跡では正の `BATCH_SETTLE_AMOUNT` も必須。`npm run readiness:jpyc -- --with-batch-settlement-receipt` でも単発receipt確認を readiness stage として実行できる。

本番有効化直前は `npm run verify:batch` を通す。`verify:batch` は `readiness:batch` と同じ検証を実行する。これは `preflight:batch`、local `BATCH_SETTLEMENT_FEE_AMOUNT` の正の integer 検証、`BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` と `FACILITATOR_EVM_PRIVATE_KEY` の鍵分離、実canisterの batch env name、実canisterの active seller に紐づく `batch_writer_receiver_scope_count() > 0`、実canisterの receiver authorizer / batch settlement contract / fee と local env の一致、実canisterの `batch_channel_count` / `batch_channel` / `batch_channels` / `batch_deleted_channel_count` / `batch_deleted_channel` / `batch_deleted_channels` query API と count/list 件数整合、実canister module hash と local wasm SHA-256 の一致、controller 2個以上・freezing threshold 90日以上・cycles残高、`/supported` の batch 広告、`/verify` の batch-only route、deposit / claim / settle / refund の4 receipt、wasm SHA-256、`dist/facilitator.did` の追跡/差分、DID の batch channel / SQLite 管理API をまとめて JSON 出力する。`verify:batch` の実行 identity は controller か、対象 receiver の enabled writer scope を持つ principal にする。`/supported` は `BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY` から導出した address、`BATCH_WITHDRAW_DELAY_SECONDS`、`JPYC_EIP712_VERSION` との一致も検証する。cycles 下限は既定 `1000000000000` で、必要なら `BATCH_MIN_CANISTER_CYCLES` で上げる。`/verify` は exact scheme を `unsupported_verify_scheme` で拒否する negative probe を実行する。`X402_BATCH_VERIFY_FIXTURE` に既存 channel を使う batch `/verify` request JSON を渡すと、positive probe として `isValid=true`、`extra.channelState`、SDK 互換 flat fields の一致も検証する。実canister確認は `ICP_ENVIRONMENT` と `ICP_CANISTER` を使い、既定は `ic` / `edge`。mainnet では `X402_BASE_URL=https://host[:port]` が必須。local canister は `ICP_ENVIRONMENT=local npm run verify:batch` で確認する。env 名の単体確認は `npm run smoke:canister:env -- --with-batch`、HTTP smoke の単体確認は `npm run smoke:canister -- --with-batch` を使う。4 receipt は `BATCH_DEPOSIT_*`、`BATCH_CLAIM_*`、`BATCH_REFUND_*`、`BATCH_SETTLE_*` の prefixed env を使う。batch tx 送信前の確認だけなら `npm run verify:batch:preflight` を使う。`ready: true` でない場合は `nextCommands` を順に潰す。

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

現行 v1 は JPYC Polygon mainnet の `exact` + EIP-3009 が本決済対象。batch settlement は verify/storage、onchain tx 送信、軽量 receipt 判定、receipt script での post-state 監査まで対応。Base、Solana、upto、tECDSA は対象外。
EIP-3009 のため buyer は token approval 不要。facilitator 単体では merchant order/resource binding を暗号学的に保証しない。merchant は payment requirements 生成時に resource URL や order ID を拘束する。
merchant は nonce 生成時に order ID、resource URL、amount、payer、seller を DB commitment し、`paymentRequirements.extra.sellerAuthorization` に seller 署名済み commitment を入れる。facilitator は seller authorization と payment payload/resource の整合性を検証するが、注文 DB の最終判定は merchant app 側で行う。
支払い後の ticket/credit 付与は merchant app 側の責務。facilitator 本体は settlement record と seller credit のみ保持する。

## Release

本番投入時は main 直 deploy ではなく annotated tag を使う。`v0.1.0` 作成前に `git tag --list` と `git ls-remote --tags origin` で重複を確認し、tag message に目的、主要変更、検証コマンド、wasm hash 記録手順を含める。
mainnet公開はこのMVPの対象外であり、`npm run ic:deploy:mainnet`は設定検証後に必ず停止する。既存canisterは旧payment-intent rowを監査・解消するtransition releaseなしに直接upgradeしない。Production手順を有効化する際は、profile・token・contract・料金・承認済み3文書versionを`set_runtime_profile`で原子的に反映し、readiness checklistをすべて満たすことを別リリースで確認する。

## 検証

```bash
cargo test -p jpyc_x402_facilitator
npm test
npm run build
npm run did:generate
npm run did:check
```

CI は `candid-extractor` `0.1.6` で DID 生成を固定する。local で DID を再生成する場合も同版を使う。
`npm run build` は TS typecheck と Rust facilitator build を実行する。TS は canister 運用補助と smoke 用で、facilitator 本体は Rust canister のみ。
