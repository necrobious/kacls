use lambda_runtime::{LambdaEvent, Error as LambdaError};
use base64;
use crate::v20230102::{
    config::Config,
    error::Error,
    http::{ CONTENT_TYPE, APPLICATION_JSON },
    auth::{ validate_authn_token, validate_authz_token },
};
use serde_json::{json, Value, from_str, from_slice};
use serde_derive::{Deserialize,Serialize};
use aws_lambda_events::{
    encodings::Body,
    apigw::{ ApiGatewayV2httpRequest, ApiGatewayV2httpResponse },
};
 use http::{
    header::{ HeaderMap, HeaderName, HeaderValue },
    status::StatusCode,
};

use tracing::{ info, error };


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WrapRequest {
    pub authentication: String,
    pub authorization: String,
    pub key: String,
    pub reason: Value
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WrapResponse {
    pub wrapped_key: String,
}

impl TryFrom<WrapResponse> for ApiGatewayV2httpResponse {
    type Error = LambdaError;
    fn try_from(e: WrapResponse) -> Result<Self, Self::Error> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(CONTENT_TYPE),
            HeaderValue::from_static(APPLICATION_JSON)
        );
        let body = serde_json::to_string(&e)?;
        let resp = ApiGatewayV2httpResponse {
            body: Some(Body::Text(body)),
            status_code: StatusCode::OK.as_u16().into(),
            headers: headers, 
            is_base64_encoded: Some(false),
            ..Default::default()
        };
        Ok(resp)
    }
}

const MSG_WRAP_REQ_MESSAGE: &'static str = "Wrap request body did not contain the expected payload";
const MSG_WRAP_REQ_DETAILS: &'static str = "Expected payload to match JSON documented at https://developers.google.com/workspace/cse/reference/wrap";

fn get_wrap_request_error() -> Error {
    Error {
        code: StatusCode::BAD_REQUEST,
        message: MSG_WRAP_REQ_MESSAGE.to_string(),
        details: MSG_WRAP_REQ_DETAILS.to_string(), 
    }
}

fn get_wrap_request_from_event_body(event: &LambdaEvent<ApiGatewayV2httpRequest>) -> Result<WrapRequest, Error> {
    match (&event.payload.body, event.payload.is_base64_encoded)  {
        (Some(text), false) => {
            serde_json::from_str(&text).map_err(|e| {
                error!(target: "api:wrap", "while attempting deserialization into WrapRequest from text body: {}", &e);
                get_wrap_request_error()
            })
        },
        (Some(text), true) => {
            let bytes = base64::decode(&text).map_err(|e| {
                error!(target: "api:wrap", "while attempting base64 decoding of request body: {}", &e);
                get_wrap_request_error()
            })?;
            serde_json::from_slice(&bytes).map_err(|e| {
                error!(target: "api:wrap", "while attempting deserialization into WrapRequest from binary body: {}", &e);
                get_wrap_request_error()
            })
        },
        _ => {
            error!(target: "api:wrap", "get wrap request called without request body");
            Err(get_wrap_request_error())
        }
    }
}

pub async fn wrap(config: &Config, event: LambdaEvent<ApiGatewayV2httpRequest>) -> Result<WrapResponse, Error> {
    info!(target:"api:wrap", "/wrap route invoked");
    let wrap_req = get_wrap_request_from_event_body(&event)?;
    let authn_tok = validate_authn_token(&config.trusted_keys, &wrap_req.authentication)?; 
    let authz_tok = validate_authz_token(&config.trusted_keys, &wrap_req.authorization)?; 
    let wrap_res = WrapResponse {
        wrapped_key: wrap_req.key,
    };
    Ok(wrap_res)
}
