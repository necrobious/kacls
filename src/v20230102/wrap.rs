use base64::{Engine as _, engine::general_purpose};
use crate::v20230102::{
    config::Config,
    error::Error,
    auth::{ validate_authn_token, validate_authz_token },
    crypto::encrypt,
};
use serde_json::Value;
use serde_derive::{ Deserialize, Serialize};

use http::{
    status::StatusCode,
    header::CONTENT_TYPE,
};

use lambda_http::{
    Body,
    Request,
    Response,
    Error as LambdaHttpError,
};

use tracing::{ info, error };

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WrapRequest {
    // A JWT issued by the IdP asserting who the user is.
    pub authentication: String,
    // A JWT asserting that the user is allowed to wrap a key for resource_name.
    pub authorization: String,
    // The base64 encoded DEK. Max size: 128 bytes.
    pub key: String,
    // A passthrough JSON string providing additional context about the operation.
    // The JSON provided should be sanitized before being displayed. Max size: 1 KB.
    pub reason: Value
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WrapResponse {
    // The base64 encoded binary object. Max size: 1 KB.
    pub wrapped_key: String,
}


impl TryFrom<WrapResponse> for Response<Body> {
    type Error = LambdaHttpError;

    fn try_from(resp: WrapResponse) -> Result<Self, Self::Error> {
        let body = serde_json::to_string(&resp)
            .map(|s| Body::Text(s.to_string())) 
            .map_err(Box::new)?;

        let resp = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .status(StatusCode::OK)
            .body(body)
            .map_err(Box::new)?;

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


impl TryFrom<&Body> for WrapRequest {
    type Error = Error;
    fn try_from(body: &Body) -> Result<Self, Self::Error> {
        match body {
            Body::Empty => {
                error!(target: "api:wrap", "get wrap request called without request body");
                Err(get_wrap_request_error())
            },
            Body::Text(text) => {
                serde_json::from_str(&text).map_err(|e| {
                    error!(target: "api:wrap", "while attempting deserialization into WrapRequest from text body: {}", &e);
                    get_wrap_request_error()
                })
            },
            Body::Binary(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| {
                    error!(target: "api:wrap", "while attempting deserialization into WrapRequest from binary body: {}", &e);
                    get_wrap_request_error()
                })
            }
        }
    }
}

// Returns encrypted Data Encryption Key (DEK) and associated data.
pub async fn wrap(config: &Config, event: Request) -> Result<WrapResponse, Error> {
    info!(target:"api:wrap", "/wrap route invoked");
    let wrap_req = WrapRequest::try_from(event.body())?; // get_wrap_request_from_event_body(&event)?;

//--- Authentication & Authorization checks
    let authn_token = validate_authn_token(&config.trusted_keys, &wrap_req.authentication)?;
    let authz_token = validate_authz_token(&config.trusted_keys, &wrap_req.authorization)?;

    config.authorization_policy.can_wrap(&authn_token.claims, &authz_token.claims)?;
//--- Authenticated and Authorized to wrap

    let ciphertext = encrypt(
        &config.kms_client,
        &config.kms_arns.get(0).unwrap(),
        &wrap_req.key,
        &authz_token.claims.resource_name,
        &authz_token.claims.perimeter_id
    ).await?;

    let wrapped_key = general_purpose::STANDARD.encode(ciphertext);

    let wrap_res = WrapResponse {
        wrapped_key,
    };

    Ok(wrap_res)
}
