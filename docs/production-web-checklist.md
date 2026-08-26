# Web MVP production checklist

Previewはレビュー前草案とAmoy専用であり、次をすべて満たすまでProductionへ公開しない。

- Seller利用規約、プライバシーポリシー、資産管理境界の専門家レビューとversion確定
- `NETWORK_PROFILE=polygon`、chain ID 137、本番JPYC、公式BatchSettlement contractの一致
- mainnet canisterとCloudflare Production環境の分離
- controller複数化、freezing threshold、cycles残高、RPC readinessの確認
- facilitator gas残高、seller credit料金、receiver authorizer鍵分離の確認
- Production originを含むseller同意messageの実署名確認
- CSP、CORS、deep link、wallet接続、settlement履歴のスモーク確認
