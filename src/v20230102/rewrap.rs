use crate::v20230102::{
    config::Config,
    error::Error,
    auth::{ validate_authz_token },
    crypto::{ encode, decode, encrypt, decrypt, checksum },
    keyid::KeyId,
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
pub struct RewrapRequest {
    // A JWT asserting that the user is allowed to unwrap a key for resource_name.
    pub authorization: String,
    // The base64 binary object returned by wrap.
    pub wrapped_key: String,
    // A passthrough JSON string providing additional context about the operation.
    // The JSON provided should be sanitized before being displayed. Max size: 1 KB.
    pub reason: Value,
    // URL of current wrapped_key's KACLS.
    pub original_kacls_url: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RewrapResponse {
    // SHA-256 of the unwrapped DEK with the Resource ID and "KaclMigration" prepended.
    // This string should be a 43-character base64 string. 
    pub checksum: String,
    // The base64 encoded binary object. Max size: 1 KB.
    pub wrapped_key: String,
}

impl TryFrom<RewrapResponse> for Response<Body> {
    type Error = LambdaHttpError;

    fn try_from(resp: RewrapResponse) -> Result<Self, Self::Error> {
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

const MSG_DIGEST_REQ_MESSAGE: &'static str = "Rewrap request body did not contain the expected payload";
const MSG_DIGEST_REQ_DETAILS: &'static str = "Expected payload to match JSON documented at https://developers.google.com/workspace/cse/reference/rewrap";

fn get_rewrap_request_error() -> Error {
    Error {
        code: StatusCode::BAD_REQUEST,
        message: MSG_DIGEST_REQ_MESSAGE.to_string(),
        details: MSG_DIGEST_REQ_DETAILS.to_string(), 
    }
}


impl TryFrom<&Body> for RewrapRequest {
    type Error = Error;
    fn try_from(body: &Body) -> Result<Self, Self::Error> {
        match body {
            Body::Empty => {
                error!(target: "api:rewrap", "rewrap request called without request body");
                Err(get_rewrap_request_error())
            },
            Body::Text(text) => {
                serde_json::from_str(&text).map_err(|e| {
                    error!(target: "api:rewrap", "while attempting deserialization into RewrapRequest from text body: {}", &e);
                    get_rewrap_request_error()
                })
            },
            Body::Binary(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| {
                    error!(target: "api:rewrap", "while attempting deserialization into RewrapRequest from binary body: {}", &e);
                    get_rewrap_request_error()
                })
            }
        }
    }
}

// Re-encrypts an encrypted Data Encryption Key (DEK).
//
// Use this method to migrate from an old Key Access Control List Service (KACLS) to a new KACLS,
// taking a DEK wrapped with the old KACLS wrap method, and returns a DEK wrapped with the new
// KACLS wrap method.
pub async fn rewrap(config: &Config, event: Request) -> Result<RewrapResponse, Error> {
    info!(target:"api:rewrap", "/rewrap route invoked");

    let rewrap_req = RewrapRequest::try_from(event.body())?;

//--- Authorization check
    let authz_token = validate_authz_token(&config.trusted_keys, &rewrap_req.authorization)?;

    config.authorization_policy.can_rewrap(&authz_token.claims)?;
//--- Authorized to digest 

    let decoded_wrapped_key = decode(&rewrap_req.wrapped_key).map_err(|b64_dec_err| {
        error!(target = "api:digest", "Base64 error while attempting to decrypt key: {:?}", &b64_dec_err);
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
            &authz_token.claims.resource_name,
            &authz_token.claims.perimeter_id
        ).await?;

        let accum_digest = checksum(&dek, &authz_token.claims.resource_name);
        let checksum = encode(accum_digest);

        let key_id = KeyId::try_from(&config.kms_enc_arn).unwrap().to_bytes();

        let ciphertext = encrypt(
            &config.kms_client,
            &config.kms_enc_arn,
            &dek,
            &authz_token.claims.resource_name,
            &authz_token.claims.perimeter_id
        ).await?;

        let mut accum: Vec<u8> = vec![0; 5 + key_id.len() + ciphertext.len()];
        accum[0..5].clone_from_slice(KID_VERSION_1_HEADER);
        accum[5..22].clone_from_slice(&key_id[..]);
        accum[22..].clone_from_slice(&ciphertext[..]);

        let wrapped_key = encode(accum);

        let rewrap_res = RewrapResponse {
            wrapped_key,
            checksum,
        };

        Ok(rewrap_res)
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
