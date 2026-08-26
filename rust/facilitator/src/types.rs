// rust/facilitator/src/types.rs: x402 facilitator HTTP JSON と IC HTTP gateway 型を定義する。
use candid::{CandidType, Deserialize as CandidDeserialize};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub asset: String,
    pub amount: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(default)]
    pub extra: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceInfo {
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "mimeType")]
    pub mime_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u64,
    #[serde(default)]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: Eip3009Payload,
    #[serde(default)]
    pub extensions: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Payload {
    pub signature: String,
    pub authorization: Eip3009Authorization,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorRequest {
    pub x402_version: u64,
    pub payment_payload: PaymentPayload,
    pub payment_requirements: PaymentRequirements,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequiredResponse {
    pub x402_version: u64,
    pub error: String,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
pub struct SettleResponse {
    pub success: bool,
    pub transaction: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, String>>,
    pub extra_json: Option<String>,
}

impl Serialize for SettleResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut len = 3;
        len += usize::from(self.payer.is_some());
        len += usize::from(self.amount.is_some());
        len += usize::from(self.error_reason.is_some());
        len += usize::from(self.error_message.is_some());
        len += usize::from(self.extra.is_some() || self.extra_json.is_some());
        let mut out = serializer.serialize_struct("SettleResponse", len)?;
        out.serialize_field("success", &self.success)?;
        out.serialize_field("transaction", &self.transaction)?;
        out.serialize_field("network", &self.network)?;
        if let Some(payer) = &self.payer {
            out.serialize_field("payer", payer)?;
        }
        if let Some(amount) = &self.amount {
            out.serialize_field("amount", amount)?;
        }
        if let Some(error_reason) = &self.error_reason {
            out.serialize_field("errorReason", error_reason)?;
        }
        if let Some(error_message) = &self.error_message {
            out.serialize_field("errorMessage", error_message)?;
        }
        if self.extra.is_some() || self.extra_json.is_some() {
            out.serialize_field("extra", &self.extra_value())?;
        }
        out.end()
    }
}

impl SettleResponse {
    fn extra_value(&self) -> Value {
        let mut value = self
            .extra_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<Value>(json).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        if let Value::Object(object) = &mut value {
            if let Some(extra) = &self.extra {
                for (key, item) in extra {
                    object.insert(key.clone(), Value::String(item.clone()));
                }
            }
        }
        value
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponseExtra {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charged_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_state: Option<SettleChannelStateExtra>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_state: Option<SettleVoucherStateExtra>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleChannelStateExtra {
    pub channel_id: String,
    pub balance: String,
    pub total_claimed: String,
    pub withdraw_requested_at: u64,
    pub refund_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charged_cumulative_amount: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleVoucherStateExtra {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_max_claimable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<String>,
    pub signers: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub x402_version: u64,
    pub scheme: String,
    pub network: String,
    pub extra: Value,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
pub struct HeaderField(pub String, pub String);

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
    pub certificate_version: Option<u16>,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
    pub upgrade: Option<bool>,
}

pub fn json_response(status_code: u16, value: &impl Serialize) -> HttpResponse {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"json\"}".to_vec());
    HttpResponse {
        status_code,
        headers: vec![
            HeaderField("content-type".to_string(), "application/json".to_string()),
            HeaderField("cache-control".to_string(), "no-store".to_string()),
            HeaderField("access-control-allow-origin".to_string(), "*".to_string()),
            HeaderField(
                "access-control-expose-headers".to_string(),
                "payment-required, payment-response".to_string(),
            ),
        ],
        body,
        upgrade: None,
    }
}

pub fn text_response(status_code: u16, text: &str) -> HttpResponse {
    HttpResponse {
        status_code,
        headers: vec![
            HeaderField(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            HeaderField("cache-control".to_string(), "no-store".to_string()),
            HeaderField("access-control-allow-origin".to_string(), "*".to_string()),
            HeaderField(
                "access-control-expose-headers".to_string(),
                "payment-required, payment-response".to_string(),
            ),
        ],
        body: text.as_bytes().to_vec(),
        upgrade: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_response_merges_legacy_extra_and_nested_batch_extra() {
        let mut legacy = BTreeMap::new();
        legacy.insert("settlementKey".to_string(), "0xabc".to_string());
        let response = SettleResponse {
            success: true,
            transaction: "0xtx".to_string(),
            network: "eip155:137".to_string(),
            payer: Some("0xpayer".to_string()),
            amount: Some("100".to_string()),
            error_reason: None,
            error_message: None,
            extra: Some(legacy),
            extra_json: Some(
                serde_json::json!({
                    "chargedAmount": "7",
                    "channelState": {
                        "channelId": "0xchannel",
                        "balance": "1000",
                        "totalClaimed": "300",
                        "withdrawRequestedAt": 0,
                        "refundNonce": "2"
                    }
                })
                .to_string(),
            ),
        };

        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["extra"]["settlementKey"], "0xabc");
        assert_eq!(value["extra"]["chargedAmount"], "7");
        assert_eq!(value["extra"]["channelState"]["balance"], "1000");
    }

    #[test]
    fn browser_responses_expose_x402_headers() {
        for response in [
            json_response(200, &serde_json::json!({ "ok": true })),
            text_response(200, "ok"),
        ] {
            assert!(response.headers.iter().any(|header| {
                header.0 == "access-control-expose-headers"
                    && header.1.contains("payment-required")
                    && header.1.contains("payment-response")
            }));
        }
    }
}
