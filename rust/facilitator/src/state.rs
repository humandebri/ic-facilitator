// rust/facilitator/src/state.rs: settlement の冪等性 record を stable memory に載せる。
use candid::{CandidType, Deserialize as CandidDeserialize};

use crate::facilitator::{failed_settlement, successful_settlement};
use crate::rpc::BatchChannelSnapshot;
use crate::types::SettleResponse;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastSettlement {
    pub amount: String,
    pub batch_pre_refund_snapshot: Option<BatchChannelSnapshot>,
    pub payer: String,
    pub pay_to: String,
    pub tx: String,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
pub struct SettlementRecord {
    pub status: String,
    pub response: SettleResponse,
    pub pay_to: Option<String>,
    pub batch_pre_refund_snapshot: Option<BatchChannelSnapshot>,
    pub settlement_kind: Option<String>,
    pub charged_fee: Option<String>,
    pub attempt_started_at: Option<u64>,
    pub target_total_claimed: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
}

impl SettlementRecord {
    pub fn checking(payer: String, pay_to: String, amount: String, now: u64, ttl: u64) -> Self {
        Self::new(
            "checking",
            pending_response(
                "",
                "settlement_checking",
                "settlement validation is in progress",
                payer,
                amount,
            ),
            Some(pay_to),
            now,
            ttl,
        )
    }

    pub fn broadcast(
        tx: String,
        payer: String,
        pay_to: String,
        amount: String,
        now: u64,
        ttl: u64,
    ) -> Self {
        Self::new(
            "broadcast",
            pending_response(
                &tx,
                "settlement_pending",
                "settlement tx is pending confirmation",
                payer,
                amount,
            ),
            Some(pay_to),
            now,
            ttl,
        )
    }

    pub fn settled(
        tx: String,
        payer: String,
        pay_to: String,
        amount: String,
        now: u64,
        ttl: u64,
    ) -> Self {
        Self::new(
            "settled",
            successful_settlement(tx, payer, amount),
            Some(pay_to),
            now,
            ttl,
        )
    }

    pub fn settled_response(response: SettleResponse, pay_to: String, now: u64, ttl: u64) -> Self {
        Self::new("settled", response, Some(pay_to), now, ttl)
    }

    pub fn failed(
        tx: String,
        message: String,
        payer: String,
        pay_to: String,
        now: u64,
        ttl: u64,
    ) -> Self {
        let mut response = failed_settlement(
            &crate::configured_network(),
            "settlement_failed",
            &message,
            Some(payer),
        );
        response.transaction = tx;
        Self::new("failed", response, Some(pay_to), now, ttl)
    }

    pub fn status_code(&self) -> u16 {
        match self.status.as_str() {
            "settled" => 200,
            "checking" | "broadcast" => 202,
            _ => 502,
        }
    }

    pub fn is_broadcast(&self) -> bool {
        self.status == "broadcast"
    }

    pub fn broadcast_settlement(&self) -> Option<BroadcastSettlement> {
        if !self.is_broadcast() {
            return None;
        }
        Some(BroadcastSettlement {
            amount: self.response.amount.clone()?,
            batch_pre_refund_snapshot: self.batch_pre_refund_snapshot.clone(),
            payer: self.response.payer.clone()?,
            pay_to: self.pay_to.clone()?,
            tx: self.response.transaction.clone(),
        })
        .filter(|settlement| !settlement.tx.trim().is_empty())
    }

    #[cfg(test)]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }

    pub fn with_metadata(
        mut self,
        settlement_kind: &str,
        charged_fee: Option<String>,
        target_total_claimed: Option<String>,
    ) -> Self {
        self.settlement_kind = Some(settlement_kind.to_string());
        self.charged_fee = charged_fee;
        self.target_total_claimed = target_total_claimed;
        if self.status == "checking" {
            self.attempt_started_at = Some(self.created_at);
        }
        self
    }

    pub fn inherit_metadata_from(&mut self, previous: &Self) {
        self.created_at = previous.created_at;
        self.settlement_kind = previous.settlement_kind.clone();
        self.charged_fee = previous.charged_fee.clone();
        self.attempt_started_at = previous.attempt_started_at;
        self.target_total_claimed = previous.target_total_claimed.clone();
        if self.batch_pre_refund_snapshot.is_none() {
            self.batch_pre_refund_snapshot = previous.batch_pre_refund_snapshot.clone();
        }
    }

    fn new(
        status: &str,
        response: SettleResponse,
        pay_to: Option<String>,
        now: u64,
        ttl: u64,
    ) -> Self {
        Self {
            status: status.to_string(),
            response,
            pay_to,
            batch_pre_refund_snapshot: None,
            settlement_kind: None,
            charged_fee: None,
            attempt_started_at: (status == "checking").then_some(now),
            target_total_claimed: None,
            created_at: now,
            updated_at: now,
            expires_at: now.saturating_add(ttl),
        }
    }
}

fn pending_response(
    tx: &str,
    reason: &str,
    message: &str,
    payer: String,
    amount: String,
) -> SettleResponse {
    let mut response =
        failed_settlement(&crate::configured_network(), reason, message, Some(payer));
    response.transaction = tx.to_string();
    response.amount = Some(amount);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::{CandidType, Deserialize as CandidDeserialize};

    #[derive(CandidType, CandidDeserialize)]
    struct LegacySettlementRecord {
        status: String,
        response: SettleResponse,
        pay_to: Option<String>,
        created_at: u64,
        updated_at: u64,
        expires_at: u64,
    }

    #[test]
    fn maps_record_status_to_http_status() {
        let checking = SettlementRecord::checking(
            "0xabc".to_string(),
            "0xdef".to_string(),
            "100".to_string(),
            10,
            60,
        );
        let broadcast = SettlementRecord::broadcast(
            "0xtx".to_string(),
            "0xabc".to_string(),
            "0xdef".to_string(),
            "100".to_string(),
            10,
            60,
        );
        let settled = SettlementRecord::settled(
            "0xtx".to_string(),
            "0xabc".to_string(),
            "0xdef".to_string(),
            "100".to_string(),
            10,
            60,
        );
        let failed = SettlementRecord::failed(
            "0xtx".to_string(),
            "failed".to_string(),
            "0xabc".to_string(),
            "0xdef".to_string(),
            10,
            60,
        );
        assert_eq!(checking.status_code(), 202);
        assert_eq!(broadcast.status_code(), 202);
        assert_eq!(settled.status_code(), 200);
        assert_eq!(failed.status_code(), 502);
    }

    #[test]
    fn detects_expired_records() {
        let record = SettlementRecord::checking(
            "0xabc".to_string(),
            "0xdef".to_string(),
            "100".to_string(),
            10,
            60,
        );
        assert!(!record.is_expired(69));
        assert!(record.is_expired(70));
    }

    #[test]
    fn exposes_only_broadcast_settlement_details() {
        let snapshot = BatchChannelSnapshot {
            channel_id: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            balance: "1000".to_string(),
            total_claimed: "300".to_string(),
            withdraw_requested_at: 0,
            refund_nonce: "1".to_string(),
        };
        let mut broadcast = SettlementRecord::broadcast(
            "0xtx".to_string(),
            "0xabc".to_string(),
            "0xdef".to_string(),
            "100".to_string(),
            10,
            60,
        );
        broadcast.batch_pre_refund_snapshot = Some(snapshot.clone());
        assert_eq!(
            broadcast.broadcast_settlement(),
            Some(BroadcastSettlement {
                amount: "100".to_string(),
                batch_pre_refund_snapshot: Some(snapshot),
                payer: "0xabc".to_string(),
                pay_to: "0xdef".to_string(),
                tx: "0xtx".to_string(),
            })
        );

        let checking = SettlementRecord::checking(
            "0xabc".to_string(),
            "0xdef".to_string(),
            "100".to_string(),
            10,
            60,
        );
        let settled = SettlementRecord::settled(
            "0xtx".to_string(),
            "0xabc".to_string(),
            "0xdef".to_string(),
            "100".to_string(),
            10,
            60,
        );
        let failed = SettlementRecord::failed(
            "0xtx".to_string(),
            "failed".to_string(),
            "0xabc".to_string(),
            "0xdef".to_string(),
            10,
            60,
        );

        assert_eq!(checking.broadcast_settlement(), None);
        assert_eq!(settled.broadcast_settlement(), None);
        assert_eq!(failed.broadcast_settlement(), None);
    }

    #[test]
    fn decodes_legacy_record_without_batch_refund_snapshot() {
        let legacy = LegacySettlementRecord {
            status: "settled".to_string(),
            response: successful_settlement(
                "0xtx".to_string(),
                "0xabc".to_string(),
                "100".to_string(),
            ),
            pay_to: Some("0xdef".to_string()),
            created_at: 10,
            updated_at: 10,
            expires_at: 70,
        };
        let bytes = candid::encode_one(legacy).unwrap();
        let decoded: SettlementRecord = candid::decode_one(&bytes).unwrap();

        assert_eq!(decoded.batch_pre_refund_snapshot, None);
        assert_eq!(decoded.settlement_kind, None);
        assert_eq!(decoded.charged_fee, None);
        assert_eq!(decoded.attempt_started_at, None);
        assert_eq!(decoded.target_total_claimed, None);
    }
}
