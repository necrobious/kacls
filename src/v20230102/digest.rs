use base64::{Engine as _, engine::general_purpose};
use crate::v20230102::{
    config::Config,
    error::Error,
    auth::{ validate_authz_token },
    crypto::{ decrypt, checksum },
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
pub struct DigestRequest {
    // A JWT asserting that the user is allowed to unwrap a key for resource_name.
    pub authorization: String,
    // The base64 binary object returned by wrap.
    pub wrapped_key: String,
    // A passthrough JSON string providing additional context about the operation.
    // The JSON provided should be sanitized before being displayed. Max size: 1 KB.
    pub reason: Value
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DigestResponse {
    // SHA-256 of the unwrapped DEK with the Resource ID and "KaclMigration" prepended.
    // This string should be a 43-character base64 string. 
    pub checksum: String,
}


impl TryFrom<DigestResponse> for Response<Body> {
    type Error = LambdaHttpError;

    fn try_from(resp: DigestResponse) -> Result<Self, Self::Error> {
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

const MSG_DIGEST_REQ_MESSAGE: &'static str = "Digest request body did not contain the expected payload";
const MSG_DIGEST_REQ_DETAILS: &'static str = "Expected payload to match JSON documented at https://developers.google.com/workspace/cse/reference/digest";

fn get_digest_request_error() -> Error {
    Error {
        code: StatusCode::BAD_REQUEST,
        message: MSG_DIGEST_REQ_MESSAGE.to_string(),
        details: MSG_DIGEST_REQ_DETAILS.to_string(), 
    }
}


impl TryFrom<&Body> for DigestRequest {
    type Error = Error;
    fn try_from(body: &Body) -> Result<Self, Self::Error> {
        match body {
            Body::Empty => {
                error!(target: "api:digest", "digest request called without request body");
                Err(get_digest_request_error())
            },
            Body::Text(text) => {
                serde_json::from_str(&text).map_err(|e| {
                    error!(target: "api:digest", "while attempting deserialization into DigestRequest from text body: {}", &e);
                    get_digest_request_error()
                })
            },
            Body::Binary(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| {
                    error!(target: "api:digest", "while attempting deserialization into DigestRequest from binary body: {}", &e);
                    get_digest_request_error()
                })
            }
        }
    }
}

// Returns the checksum ("digest") of an unwrapped Data Encryption Key (DEK).
// `SHA-256("KACLMigration" + resource_identifier + unwrapped_dek)`
pub async fn digest(config: &Config, event: Request) -> Result<DigestResponse, Error> {
    info!(target:"api:digest", "/digest route invoked");
    let digest_req = DigestRequest::try_from(event.body())?;

//--- Authorization check
    let authz_token = validate_authz_token(&config.trusted_keys, &digest_req.authorization)?;

    config.authorization_policy.can_digest(&authz_token.claims)?;
//--- Authorized to digest 

    let dek = decrypt(
        &config.kms_client,
        &config.kms_arns.get(0).unwrap(),
        &digest_req.wrapped_key,
        &authz_token.claims.resource_name,
        &authz_token.claims.perimeter_id
    ).await?;
/*
    let mut prefix_bytes: Vec<u8> = "KACLMigration".as_bytes().into();
    let mut resource_bytes: Vec<u8> = authz_token.claims.resource_name.as_bytes().into();
    let mut accum: Vec<u8> = Vec::with_capacity(prefix_bytes.len()+resource_bytes.len()+dek.len());
    accum.append(&mut prefix_bytes);
    accum.append(&mut resource_bytes);
    accum.append(&mut dek);
    
    let accum_digest = ring::digest::digest(&ring::digest::SHA256, &accum);   
*/
    let accum_digest = checksum(&dek, &authz_token.claims.resource_name);
    let checksum = general_purpose::STANDARD.encode(accum_digest);

    let digest_res = DigestResponse {
        checksum,
    };

    Ok(digest_res)
}
