# Batch settlementの資産管理境界

この文書は、facilitatorと公式BatchSettlementコントラクトの技術的な役割を説明する。
法令上の評価、登録要否または法的助言を示すものではない。

## 資産の所在

利用者がdepositしたJPYCは、facilitatorのwalletまたはICP canisterへ移転しない。
JPYCは、`@x402/evm`が指定する公式BatchSettlementコントラクト上で管理される。

facilitatorは、利用者のJPYC残高を保持する秘密鍵を管理しない。
`FACILITATOR_EVM_PRIVATE_KEY`は、検証済みのcalldataをPolygonへ送信し、gasを支払うために使う。

## Payerの承認

depositには、payerによるEIP-3009 authorization署名が必要となる。
claimには、payer authorizerが署名したvoucherが必要となる。

voucherはchannel IDと`maxClaimableAmount`を拘束する。
channel IDはpayer、payer authorizer、receiver、receiver authorizer、token、withdraw delayおよびsaltから計算される。
そのため、facilitatorは有効なpayer署名を維持したまま、支払上限、receiverまたはtokenを変更できない。

claim処理は、`totalClaimed`がpayer署名済みの`maxClaimableAmount`を超えない場合に限って送信される。
facilitatorが保持するreceiver authorizer鍵だけでは、payer署名済み上限を増やせない。

## Claim、settle、refund

facilitatorはclaim、settleおよびrefundのトランザクションを送信できる。
したがって、facilitatorはトランザクションを送信する時点に関与する。

claimの金額とreceiverは、payer署名済みvoucherとchannel configによって制限される。
settleは、既にclaimされた金額をchannelに指定されたreceiverへ移転する。
refundはreceiver authorizerの署名を必要とし、channelに指定されたpayerへ返金する。

これらの制約は「各トランザクションの送信時にpayerの追加署名が必要である」ことを意味しない。
claimは事前に署名されたvoucherを使用し、settleはclaim済み金額を処理し、refundはreceiver authorizerの署名を使用する。

## Canisterに保存する情報

ICP canisterは、署名検証、重複防止、処理予約および監査のためにchannel情報を保存する。
保存対象には、次の情報が含まれる。

- channel config
- `balance`
- `chargedCumulativeAmount`
- `signedMaxClaimable`
- `totalClaimed`
- `refundNonce`
- pending request
- settlement record

これらの値は、facilitatorが保管するJPYC残高を表さない。
オンチェーン資産と移転結果の正本は、公式BatchSettlementコントラクトのstateとPolygon上のtransaction receiptである。
canister上のchannel情報は、プロトコル処理と監査に使用するミラー情報である。

商品、注文およびpayment intentはmerchant側の責務であり、facilitator canisterでは保存・検証しない。

## Seller creditとの区別

seller creditはbatch contract上のJPYC残高とは別の内部課金残高である。
seller creditはfacilitator手数料の支払いにのみ使用し、JPYCとして送金、譲渡または換金できない。

seller creditの購入代金は`SELLER_CREDIT_PAY_TO`へ送られる。
この処理はbatch settlementで利用者がdepositするJPYCの管理とは区別される。

## 表示上の注意

本サービスを「利用者資産の保管サービス」または「任意の送金サービス」として説明しない。
ただし、「非カストディであるため法令上の資産管理に該当しない」とも断定しない。
法令上の評価は、鍵の運用、利用者との契約、提供地域および実際の業務フローを含めて別途確認する。
