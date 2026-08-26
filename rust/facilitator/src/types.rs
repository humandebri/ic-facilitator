// rust/facilitator/src/types.rs: x402 facilitator HTTP JSON と IC HTTP gateway 型を定義する。
use candid::{CandidType, Deserialize as CandidDeserialize};
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequiredResponse {
    pub x402_version: u64,
    pub error: String,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
        ],
        body: text.as_bytes().to_vec(),
        upgrade: None,
    }
}
