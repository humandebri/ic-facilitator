# 同一チャネルの自動claim

店舗のreceiverごとに明示的に有効化する。既定は無効で、既存店舗の料金設定やgas上限は変更しない。対象はclaimによる売上確保まで。ウォレットへの送金（settle）は既存操作で行う。

## 回収条件と費用

- 確定更新で `charged_cumulative_amount` が増えた回数を数え、未回収分が100件に達するとclaimする。通常の時間条件はない。
- 出金要求を検出した場合、店舗が手動回収を要求した場合、無効化に伴う回収時は100件未満でもclaimする。
- 有効化前の未回収分は件数履歴がないため、最初にまとめて回収する。
- 最新署名の `signed_max_claimable` ではなく、確定済みの `charged_cumulative_amount` までを請求する。送信中に確定した決済は次の回収分として残す。
- 1つのチャネルを1 claimで送信する。異なるチャネルの一括送信は行わない。
- 既存の1 claim手数料を店舗クレジットから予約する。現在の設定は0.5 JPYCなので100件集約時は1件あたり0.005 JPYC。deposit・settleは別料金。
- gas上限超過など送信前の失敗は予約手数料を返す。送信後の応答喪失・同じtxの再送では追加課金しない。revertは既存送信と同様に手数料を消費し、自動の有料再試行を停止する。店舗の手動要求で再試行でき、その新しい試行には手数料がかかる。
- 335 gweiは料金計算の基準であり、実際の送信gas価格を固定する設定ではない。送信は既存の見積りとgas・総POL上限を使う。

## 監視と受付停止

未回収分または処理中の決済があるチャネルを60秒間隔で監視する。最大8チャネルを並行処理し、処理しきれない間は監視日時の古さで新規受付を止める。未回収分も処理中の決済もないチャネルは監視とタイマーの対象から外し、次の予約で再開する。監視登録は最大1000チャネル、1チャネルの未回収決済履歴は最大200件として受付時に制限する。

通常の監視予定は処理完了から60秒後とし、予約作成・確定・署名更新では前倒ししない。新規監視登録、休止からの復帰、監視期限切れ、未回収件数が100件に到達した更新、手動回収要求、有効化・無効化では実行を前倒しする。すでに設定したタイマーの発火期限は、更新や再試行が続いても延長しない。

回収済み額・残高は `eth_call` の `finalized` ブロックから、出金要求は `latest` から取得する。利用するRPCには両方のブロックタグへの対応が必要。新しいチャネルの最初の予約、または休止後の予約で `monitor_stale` が返った場合、その呼出しは予約を受理せず監視だけを登録する。監視完了後に予約を再実行する。TypeScriptの既存CASクライアントはこのエラーを自動で再試行しないため、呼出し元で再試行を扱う。

出金要求、120秒以上古い監視結果、クレジット不足、回収の滞留・エラー、無効化に伴う回収中は、新しい `pending_request` を拒否する。すでに受理した予約の確定はこの判定で拒否しない。無効化後も未回収分と処理中の予約がなくなるまで監視を続け、チャネル削除を禁止する。

無効化で回収するのは、その店舗ですでに自動回収の管理下にあるチャネルと初回予約待ちの監視登録だけ。手動管理中のチャネルを新しく登録することはなく、自動回収の登録がない店舗の無効化ではRPC・課金・予約受付への影響はない。

100件未満のまま利用が止まると未回収期間は無期限で、その間の監視費用は運営負担になる。監視の追加請求は実装していない。gas上限を維持するため、出金期限までの回収は保証しない。

## API

既存のreceiver向けwriter認可またはcontroller認可を必要とするCandid APIを追加した。匿名HTTP経由で有効化できない。

- `batch_auto_claim_set_enabled(receiver, enabled) -> Result<(), text>`
- `batch_auto_claim_request(channel_id) -> Result<(), text>`
- `batch_auto_claim_status(channel_id) -> Result<opt AutoClaimStatus, text>`

TypeScriptからは認証済みactorを `src/icBatchAutoClaim.ts` の `IcBatchAutoClaim` に渡す。

```ts
const collection = new IcBatchAutoClaim(actor);
await collection.setEnabled(receiver, true);
const status = await collection.status(channelId);
await collection.requestClaim(channelId);
await collection.setEnabled(receiver, false); // 未回収分の回収・監視は続く
```

状態には未回収額、記録済み未回収決済件数、最古日時、監視日時、出金期限、送信tx、停止理由を返す。日時はUnix秒。導入前の未回収分は件数不明なので0件、最古日時は有効化日時として扱う。

`monitor_calls` は監視用outcall数、`monitor_cycles_reserved` はそのoutcallに添付したcyclesの累計。後から行われるv2返金を控除していない上限値であり、IC実行・保存・タイマー・claim処理の費用も含まない。実原価として表示してはいけない。

## 永続化・再試行

既存の `BatchChannel` 型を変更せず、MemoryId 11（店舗設定）、12（回収状態・送信journal）、13（実行予定順の索引）を追加した。既存のメモリ領域やSQLite領域120を再利用しない。タイマーだけをアップグレード後に再作成する。

gas見積りなどの非同期処理が終わってからnonceを予約し、署名済みtx・hash・fee・対象累積額を保存してから送信する。送信後は同じraw txを再送し、送信結果が不明なままnonceを再利用しない。送信前に中断した試行は、監視RPCや現在のネットワーク設定の検証より先に予約手数料と送信ロックを解放する。次の実行で監視・回収を再開し、監視障害中でも二重返金しない。手動送信と同じreceiverの送信ロックを共用する。送信前に最新ブロックの回収済み額も読み、手動claimが採掘済みなら追加送信せず予約手数料を返す。revert後の手動再試行は別の永続キーに記録し、過去の手数料履歴を上書きしない。二重返却を防ぐため、自動claimの記録には汎用の `recover_stale_settlement` を使えず、回収journalが復旧を担当する。

## 検証・有効化条件

Rustテストで件数境界、送信中の追加決済、永続マップの再接続、応答喪失、送信前中断、gas上限、出金要求、無効化、監視失敗、認可、手動送信との排他、revert時の停止を検証する。

ローカルEVM検証は次の手順で実行する。公式Polygon BatchSettlementのruntimeを別途読み取り、`/tmp/ic-auto-claim-runtime.hex` に保存する。スクリプトは固定のループバックRPCとchainId 31337を使用し、本番にtxを送らない。

```sh
forge build --root test/amoy
anvil --host 127.0.0.1 --port 18548 --chain-id 31337 --silent
node --import tsx scripts/test_auto_claim_evm.ts
```

2026-09-08のローカル検証で、署名上限200に対して確定額100のみのclaim、同一claimの再実行、出金期限前の回収、期限後の回収失敗を確認した。claimは78,390 gas。runtimeのkeccak256は `0xfb36a4b8061cd477134183bcc05d574637a0a131584ea6029369a8d94c0af5b9`。テストトークンとローカルEVMによる値で、本番JPYCのreceiptではない。

配置先サブネットでのHTTPS outcall v2、実際のcanister upgradeを挟んだタイマー再開、返金後の実原価は別途スモーク検証が必要。本番有効化はその確認後に行う。
