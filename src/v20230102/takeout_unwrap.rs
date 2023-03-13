use crate::v20230102::{
    config::Config,
    error::Error,
    auth::{ validate_authn_token },
    crypto::{ encode, decode, decrypt },
    KID_VERSION_1_HEADER,
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
pub struct TakeoutUnwrapRequest {
    // A JWT issued by the IdP asserting who the user is.
    pub authentication: String,
    // The base64 binary object returned by wrap.
    pub wrapped_key: String,
    // A passthrough JSON string providing additional context about the operation.
    // The JSON provided should be sanitized before being displayed. Max size: 1 KB.
    pub reason: Value,
    // An identifier for the object encrypted by the DEK.
    // This value must match the resource_name used to wrap the key. Maximum size: 128 bytes.
    pub resource_name: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct TakeoutUnwrapResponse {
    // The base64 encoded DEK.
    pub key: String,
}


impl TryFrom<TakeoutUnwrapResponse> for Response<Body> {
    type Error = LambdaHttpError;

    fn try_from(resp: TakeoutUnwrapResponse) -> Result<Self, Self::Error> {
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

const MSG_UNWRAP_REQ_MESSAGE: &'static str = "Takeout Unwrap request body did not contain the expected payload";
const MSG_UNWRAP_REQ_DETAILS: &'static str = "Expected payload to match JSON documented at https://developers.google.com/workspace/cse/reference/takeout_unwrap";

fn get_takeout_unwrap_request_error() -> Error {
    Error {
        code: StatusCode::BAD_REQUEST,
        message: MSG_UNWRAP_REQ_MESSAGE.to_string(),
        details: MSG_UNWRAP_REQ_DETAILS.to_string(), 
    }
}

impl TryFrom<&Body> for TakeoutUnwrapRequest {
    type Error = Error;
    fn try_from(body: &Body) -> Result<Self, Self::Error> {
        match body {
            Body::Empty => {
                error!(target: "api:takeout_unwrap", "takeout_unwrap request called without request body");
                Err(get_takeout_unwrap_request_error())
            },
            Body::Text(text) => {
                serde_json::from_str(&text).map_err(|e| {
                    error!(target: "api:takeout_unwrap", "while attempting deserialization into TakeoutUnwrapRequest from text body: {}", &e);
                    get_takeout_unwrap_request_error()
                })
            },
            Body::Binary(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| {
                    error!(target: "api:takeout_unwrap", "while attempting deserialization into TakeoutUnwrapRequest from binary body: {}", &e);
                    get_takeout_unwrap_request_error()
                })
            }
        }
    }
}

// Returns decrypted Data Encryption Key (DEK).
pub async fn takeout_unwrap(config: &Config, event: Request) -> Result<TakeoutUnwrapResponse, Error> {
    info!(target:"api:takeout_unwrap", "/takeout_unwrap route invoked");
    let takeout_unwrap_req = TakeoutUnwrapRequest::try_from(event.body())?;

//--- Authentication check
    let authn_token = validate_authn_token(&config.trusted_keys, &takeout_unwrap_req.authentication)?;

    config.authorization_policy.can_takeout_unwrap(&authn_token.claims)?;
//--- Authenticated and Authorized to takeout_unwrap

    let decoded_wrapped_key = decode(&takeout_unwrap_req.wrapped_key).map_err(|b64_dec_err| {
        error!(target = "api:takeout_unwrap", "Base64 error while attempting to decrypt key: {:?}", &b64_dec_err);
        Error {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            message: "error while attempting to decrypt key".to_string(),
            details: "error while attempting to decrypt key".to_string(),
        }
    })?;

    if decoded_wrapped_key.len() < 23 {
        return Err(Error {
            code: StatusCode::BAD_REQUEST,
            message: "error while attempting to decrypt key".to_string(),
            details: "error while attempting to decrypt key".to_string(),
        })
    }

    let header_and_version = &decoded_wrapped_key[0..5];

    if KID_VERSION_1_HEADER == header_and_version {
        let kms_key_id = &decoded_wrapped_key[5..22];
        let ciphertext = &decoded_wrapped_key[22..];
        let kms_key_arn = config.kms_key_idx.get_from_bytes(&kms_key_id).ok_or(
            Error {
                code: StatusCode::UNAUTHORIZED,
                message: "unknown decryption key encryption key".into(),
                details: "unknown decryption key encryption key".into(),
            }
        )?;

        let dek = decrypt(
            &config.kms_client,
            &kms_key_arn,
            ciphertext,
            &takeout_unwrap_req.resource_name,
            &None
        ).await?;

        let key = encode(dek);

        let takeout_unwrap_res = TakeoutUnwrapResponse {
            key,
        };

        Ok(takeout_unwrap_res)
    }
    else {
        Err(
            Error {
                code: StatusCode::BAD_REQUEST,
                message: "unknown wrapped key version".into(),
                details: "unknown wrapped key version".into(),
            }
        )
    }
}
