use candid::{CandidType, Principal};
use ic_cdk::call::Call;
use ic_cdk_management_canister::{
    HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult, TransformContext,
};

// The published CDK/canhttp request type does not yet expose pricing_version.
// Wire contract: https://github.com/dfinity/ic/blob/c14df8a5b42c88e727d635392ba0ba7674a1b414/rs/types/management_canister_types/src/http.rs
#[derive(CandidType)]
struct PricedHttpRequest<'a> {
    url: &'a str,
    max_response_bytes: Option<u64>,
    method: &'a HttpMethod,
    headers: &'a [HttpHeader],
    body: &'a Option<Vec<u8>>,
    transform: &'a Option<TransformContext>,
    is_replicated: Option<bool>,
    pricing_version: Option<u32>,
}

impl<'a> From<&'a HttpRequestArgs> for PricedHttpRequest<'a> {
    fn from(request: &'a HttpRequestArgs) -> Self {
        Self {
            url: &request.url,
            max_response_bytes: request.max_response_bytes,
            method: &request.method,
            headers: &request.headers,
            body: &request.body,
            transform: &request.transform,
            is_replicated: request.is_replicated,
            pricing_version: Some(2),
        }
    }
}

#[derive(CandidType, serde::Deserialize)]
enum OutcallType {
    #[serde(rename = "non_replicated")]
    NonReplicated,
}

#[derive(CandidType)]
struct CostHttpRequestParams {
    request_bytes: u64,
    http_roundtrip_time_ms: u64,
    raw_response_bytes: u64,
    transformed_response_bytes: u64,
    transform_instructions: u64,
    outcall_type: Option<OutcallType>,
}

fn cost_params(request: &HttpRequestArgs) -> Result<CostHttpRequestParams, String> {
    if request.is_replicated != Some(false) || request.transform.is_some() {
        return Err("RPC outcalls require non-replicated requests without a transform".into());
    }
    let max_response_bytes = request
        .max_response_bytes
        .filter(|limit| *limit <= 2_000_000)
        .ok_or("RPC outcalls require a response limit of at most 2,000,000 bytes")?;
    Ok(CostHttpRequestParams {
        request_bytes: (request.url.len()
            + request
                .headers
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum::<usize>()
            + request.body.as_ref().map_or(0, Vec::len)) as u64,
        // Budget for the adapter's full 30-second timeout, not expected latency.
        // Unspent v2 cycles are refunded asynchronously by the subnet.
        http_roundtrip_time_ms: 30_000,
        raw_response_bytes: max_response_bytes,
        transformed_response_bytes: max_response_bytes,
        transform_instructions: 0,
        outcall_type: Some(OutcallType::NonReplicated),
    })
}

#[cfg(target_arch = "wasm32")]
fn cost_http_request_v2(params: &CostHttpRequestParams) -> Result<u128, String> {
    #[link(wasm_import_module = "ic0")]
    extern "C" {
        fn cost_http_request_v2(params_src: i32, params_size: i32, dst: i32);
    }
    let bytes = candid::encode_one(params).map_err(|err| err.to_string())?;
    let mut cost = [0u8; 16];
    // SAFETY: the input and 16-byte output buffers remain live for the synchronous
    // system call. ICP writes the cycle amount as an unsigned little-endian u128.
    unsafe {
        cost_http_request_v2(
            bytes.as_ptr() as i32,
            bytes.len() as i32,
            cost.as_mut_ptr() as i32,
        );
    }
    Ok(u128::from_le_bytes(cost))
}

#[cfg(not(target_arch = "wasm32"))]
fn cost_http_request_v2(_params: &CostHttpRequestParams) -> Result<u128, String> {
    Err("cost_http_request_v2 is only available on ICP".into())
}

pub async fn http_request_metered(
    request: HttpRequestArgs,
    charge: impl FnOnce(u128),
) -> Result<HttpRequestResult, String> {
    let cycles = cost_http_request_v2(&cost_params(&request)?)?;
    charge(cycles);
    Call::unbounded_wait(Principal::management_canister(), "http_request")
        .with_arg(PricedHttpRequest::from(&request))
        .with_cycles(cycles)
        .await
        .map_err(|err| err.to_string())?
        .candid()
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HttpRequestArgs {
        HttpRequestArgs {
            url: "https://polygon.example/日本語".into(),
            max_response_bytes: Some(128),
            method: HttpMethod::POST,
            headers: vec![HttpHeader {
                name: "content-type".into(),
                value: "application/json".into(),
            }],
            body: Some(b"{}".to_vec()),
            transform: None,
            is_replicated: Some(false),
        }
    }

    #[test]
    fn wire_request_preserves_http_fields_and_selects_pricing_v2() {
        #[derive(CandidType, serde::Deserialize)]
        struct Pricing {
            pricing_version: Option<u32>,
        }
        let request = request();
        let encoded = candid::encode_one(PricedHttpRequest::from(&request)).unwrap();
        assert_eq!(
            candid::decode_one::<HttpRequestArgs>(&encoded).unwrap(),
            request
        );
        assert_eq!(
            candid::decode_one::<Pricing>(&encoded)
                .unwrap()
                .pricing_version,
            Some(2)
        );
    }

    #[test]
    fn cost_budget_covers_bytes_timeout_and_non_replicated_delivery() {
        #[derive(CandidType, serde::Deserialize)]
        enum Mode {
            #[serde(rename = "non_replicated")]
            NonReplicated,
        }
        #[derive(CandidType, serde::Deserialize)]
        struct ModeField {
            outcall_type: Option<Mode>,
        }
        let request = request();
        let params = cost_params(&request).unwrap();
        assert_eq!(
            params.request_bytes,
            (request.url.len() + "content-typeapplication/json{}".len()) as u64
        );
        assert_eq!(params.http_roundtrip_time_ms, 30_000);
        assert_eq!(params.raw_response_bytes, 128);
        assert_eq!(params.transformed_response_bytes, 128);
        assert_eq!(params.transform_instructions, 0);
        let encoded = candid::encode_one(&params).unwrap();
        assert!(matches!(
            candid::decode_one::<ModeField>(&encoded)
                .unwrap()
                .outcall_type,
            Some(Mode::NonReplicated)
        ));
    }

    #[test]
    fn cost_budget_rejects_unsupported_replication_and_response_limits() {
        let mut request = request();
        request.is_replicated = None;
        assert!(cost_params(&request).is_err());
        request.is_replicated = Some(true);
        assert!(cost_params(&request).is_err());
        request.is_replicated = Some(false);
        request.max_response_bytes = None;
        assert!(cost_params(&request).is_err());
        request.max_response_bytes = Some(2_000_001);
        assert!(cost_params(&request).is_err());
    }
}
