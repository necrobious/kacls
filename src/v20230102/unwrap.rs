use base64::{Engine as _, engine::general_purpose};
use crate::v20230102::{
    config::Config,
    error::Error,
    auth::{ validate_authn_token, validate_authz_token },
    crypto::{ decrypt },
    keyid::{ KeyIndex, KeyId },
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
pub struct UnwrapRequest {
    // A JWT issued by the IdP asserting who the user is.
    pub authentication: String,
    // A JWT asserting that the user is allowed to unwrap a key for resource_name.
    pub authorization: String,
    // The base64 binary object returned by wrap.
    pub wrapped_key: String,
    // A passthrough JSON string providing additional context about the operation.
    // The JSON provided should be sanitized before being displayed. Max size: 1 KB.
    pub reason: Value
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UnwrapResponse {
    // The base64 encoded DEK.
    pub key: String,
}


impl TryFrom<UnwrapResponse> for Response<Body> {
    type Error = LambdaHttpError;

    fn try_from(resp: UnwrapResponse) -> Result<Self, Self::Error> {
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

const MSG_UNWRAP_REQ_MESSAGE: &'static str = "Unwrap request body did not contain the expected payload";
const MSG_UNWRAP_REQ_DETAILS: &'static str = "Expected payload to match JSON documented at https://developers.google.com/workspace/cse/reference/unwrap";

fn get_unwrap_request_error() -> Error {
    Error {
        code: StatusCode::BAD_REQUEST,
        message: MSG_UNWRAP_REQ_MESSAGE.to_string(),
        details: MSG_UNWRAP_REQ_DETAILS.to_string(), 
    }
}


impl TryFrom<&Body> for UnwrapRequest {
    type Error = Error;
    fn try_from(body: &Body) -> Result<Self, Self::Error> {
        match body {
            Body::Empty => {
                error!(target: "api:unwrap", "unwrap request called without request body");
                Err(get_unwrap_request_error())
            },
            Body::Text(text) => {
                serde_json::from_str(&text).map_err(|e| {
                    error!(target: "api:unwrap", "while attempting deserialization into UnwrapRequest from text body: {}", &e);
                    get_unwrap_request_error()
                })
            },
            Body::Binary(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| {
                    error!(target: "api:unwrap", "while attempting deserialization into UnwrapRequest from binary body: {}", &e);
                    get_unwrap_request_error()
                })
            }
        }
    }
}

// Returns decrypted Data Encryption Key (DEK).
pub async fn unwrap(config: &Config, event: Request) -> Result<UnwrapResponse, Error> {
    info!(target:"api:unwrap", "/unwrap route invoked");
    let unwrap_req = UnwrapRequest::try_from(event.body())?;

//--- Authentication & Authorization checks
    let authn_token = validate_authn_token(&config.trusted_keys, &unwrap_req.authentication)?;
    let authz_token = validate_authz_token(&config.trusted_keys, &unwrap_req.authorization)?;

    config.authorization_policy.can_unwrap(&authn_token.claims, &authz_token.claims)?;
//--- Authenticated and Authorized to unwrap

//--- base64 decode the wrapped key
    let decoded_wrapped_key = general_purpose::STANDARD
        .decode(&unwrap_req.wrapped_key)
        .map_err(|b64_dec_err| {
            error!(target = "api:unwrap", "Base64 error while attempting to decrypt key: {:?}", &b64_dec_err);
            Error {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "error while attempting to decrypt key".to_string(),
                details: "error while attempting to decrypt key".to_string(),
            }
        })?;

    if decoded_wrapped_key.len() < 18 {
        return Err(Error {
            code: StatusCode::BAD_REQUEST,
            message: "error while attempting to decrypt key".to_string(),
            details: "error while attempting to decrypt key".to_string(),
        })
    }

//--- extract KMS key ID from the head of the wrapped key, use it to find the KMS CMK ARN
    let kms_key_id = &decoded_wrapped_key[0..17];
    let ciphertext = &decoded_wrapped_key[17..];
    info!("key_id: {}: ", kms_key_id.iter().map(|b| format!("{:02x?}", b)).collect::<String>());
    info!("ciphertext: {}: ", ciphertext.iter().map(|b| format!("{:02x?}", b)).collect::<String>());
    let kms_key_arn = config.kms_key_idx.get_from_bytes(&kms_key_id).ok_or(
        Error {
            code: StatusCode::UNAUTHORIZED,
            message: "unknown decryption key encryption key".into(),
            details: "unknown decryption key encryption key".into(),
        }
    )?;

//--- decrypt the Data Encryption Key
    let dek = decrypt(
        &config.kms_client,
        //&config.kms_arns.get(0).unwrap(),
        &kms_key_arn,
        //&unwrap_req.wrapped_key,
        ciphertext,
        &authz_token.claims.resource_name,
        &authz_token.claims.perimeter_id
    ).await?;

//--- base64 encode the decrypted Data Encryption Key
    let key = general_purpose::STANDARD.encode(dek);

//--- assemble a success response
    let unwrap_res = UnwrapResponse {
        key,
    };

    Ok(unwrap_res)
}
