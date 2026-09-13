# 固定料金の設定根拠

2026-09-08に再計算し、ローカル`.env`と`.env.example`へ反映した固定料金。価格は取引のたびに変動させず、通常gasの基準値と処理別gas使用量から決める。本番canisterの設定同期・デプロイは実行していない。

## 通常gasの基準

[集計データ](polygon-gas-baseline.json)は2026-09-01 01:02:58 UTC〜09-08 00:04:39 UTCから約1時間間隔で64ブロックずつ、168区間・10,752ブロックを抽出したもの。各非空ブロックのbase feeに、gas使用量で重み付けされたpriority fee中央値を加え、その値の算術平均を取った。全取引の単純平均ではなく、通常の取引が払うgas価格のサンプル推定値である。

- 平均：334.6413 gwei、中央値：331.3329 gwei、p90：399.9365 gwei。
- 固定料金の基準：平均を切り上げた **335 gwei**。
- `npm run measure:gas-baseline`で再集計できる。結果の再生成だけでは料金設定を変更しない。
- Gas Stationの瞬間的なstandard/fastは通常料金の基準に使わない。fastはストレス比較に限る。

換算基準は1 POL = 0.095019 USD、1 USD = 153.86円（約14.62円/POL）。POLの価格は[CoinGecko API](https://api.coingecko.com/api/v3/simple/price?ids=polygon-ecosystem-token&vs_currencies=usd,jpy)の調査時点の値を使用。固定料金に使用する値は据え置きで、将来の値動きを保証するものではない。cycles換算は従来の1 XDR = 1.36643 USDを使用。

## 固定料金

基準は「成功時のPolygon gas原価＋非複製HTTP outcall v2概算」に20%を加え、0.5 / 0.75 / 整数JPYCへ切り上げ。gas使用量は[ローカル測定記録](local-gas-benchmark.json)による。単発処理の料金は以下のとおり。

| 処理 | 成功時gas | 固定料金（JPYC） |
| --- | ---: | ---: |
| Exact | 63,360 | 0.5 |
| Batch deposit | 132,724 | 1 |
| Batch settle | 63,344 | 0.5 |
| Batch refund（claimなし） | 101,618 | 0.75 |
| Batch settleのno-op | 25,228（比較用EVM測定） | 0（canisterはtxを送らない） |

| 件数の上限 | Claim gas | Claim料金 | Claim＋refund gas | Claim＋refund料金 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 78,450 | 0.5 | 123,442 | 1 |
| 10 | 280,899 | 2 | 343,914 | 3 |
| 50 | 1,265,679 | 8 | 1,333,433 | 8 |
| 100 | 2,517,000 | 15 | 2,592,598 | 16 |

Claim＋refundはN件claimと1件refundを含むmulticallで、実際のfacilitatorと同じ構成。既存ベンチマークのN件refundは測定対象が異なるため修正した。100件claimだけなら1件あたり0.15 JPYC。推定の100万gasを実測へ置き換えた結果、100件claimは旧設定例の5 JPYCから15 JPYCとなった。HTTP費用の削減は、Polygon gasの増加を打ち消すほど大きくない。

## 測定と運用の範囲

- 本番のcanonical BatchSettlement runtimeを独立Anvilへコピーし、テストtokenで既存ベンチマークを実行した。外部へ取引は送信していない。本番JPYC、既存channel状態、Polygon固有のgas挙動による差は未測定。
- 測定用collectorは固定30万gasだとデプロイに失敗していた。gasの自動見積もりへ変更し、token/collectorのデプロイ成功も確認するよう修正した。
- HTTPは7ノード・非複製・各RPC1秒、現在の応答上限をサイズの代用として計算する。実際のヘッダ・Candid符号化・再試行・非同期返金による差は未測定。
- 20%の余裕は実行・保存・失敗・provider費用を含む利益保証ではない。費用レポートは`provisional`のまま、請求設定への自動適用はしない。
- 現行のgas制御は送信前の`gas_limit * max_fee_per_gas`上限チェックであり、超過時は`gas_too_expensive`を返す。自動的な待機・再送はしない。
- 現在の既定上限は500,000 gas・0.03 POLのため、上の大きなBatchは実行できない。100件claimは約303万gas、100件claim＋refundは約312万gasのgas limitが必要（実測×1.2）。料金の再設定でこの送信上限を緩和してはいない。これらを運用対象にする場合は別途上限を合わせる必要がある。

料金式：[DFINITY pricing v2実装](https://github.com/dfinity/ic/blob/a9ef6104790755ea520c0d4546e61fe130136805/rs/https_outcalls/pricing/src/fees.rs)。成功gasの入力ファイルは`FACILITATOR_GAS_BENCHMARK_PATH`で差し替え可能。既定は今回のローカル測定記録で、Amoyや本番の実測と誤認しないようレポートにnetworkを表示する。
