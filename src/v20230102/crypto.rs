use base64::{Engine as _, engine::general_purpose};
use crate::v20230102::error::Error;
use aws_sdk_kms::{ Client, types::Blob };

use http::{ status::StatusCode };

use tracing::{ error };
//use regex;

//const REGEX: &'static str: r"arn:aws:kms:(?P<region>(?:us|eu)-(?:east|west)-[0-9]):(?P<account>[0-9]{12}):key/(?P<key_id>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89ABab][a-fA-F0-9]{3}-[a-fA-F0-9]{12}|mrk-[a-fA-F0-9]{32})";

//const REGEX: &'static str: r"arn:aws:kms:(?P<region>(?:us|eu)-(?:east|west)-[0-9]):(?P<account>[0-9]{12}):key/(?P<key_id>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[abAB89][a-fA-F0-9]{3}-[a-fA-F0-9]{12}|mrk-[a-fA-F0-9]{32})";
pub async fn encrypt<'config, 'event> (
    // AWS SDK KMS Client to connect to the KMS service with
    kms_client: &'config Client,
    // AWS KMS CMK ARN to encrypt the DEK with
    kms_arn: &'config str,
    // The base64 encoded DEK. Max size: 128 bytes.
    dek: &'event str,
    // An identifier for the object encrypted by the DEK. Maximum size: 128 bytes.
    resource_name: &'event str,
    // (Optional) A value tied to the document location that can be used to choose which perimeter will be checked when unwrapping. Maximum size: 128 bytes.
    perimeter_id: &'event Option<String>
) -> Result<String, Error> {
    let dek_raw = general_purpose::STANDARD.decode(dek)
        .map_err(|b64_dec_err| {
            error!(target = "api:encrypt", "Base64 error while attempting to encrypt key: {:?}", &b64_dec_err);
            Error {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "error while attempting to encrypt key".to_string(),
                details: "error while attempting to encrypt key".to_string(),
            }
        })?;

    let mut kms_req = kms_client
        .encrypt()
        .key_id(kms_arn)
        .plaintext(Blob::new(dek_raw))
        .encryption_context("resource_name", resource_name);

    if perimeter_id.is_some() {
        let pid = perimeter_id.as_ref().unwrap();
        kms_req = kms_req.encryption_context("perimeter_id", pid) 
    }

    let kms_res = kms_req
        .send()
        .await
        .map_err(|sdk_err| {
            error!(target = "api:encrypt", "KMS error while attempting to encrypt key: {:?}", &sdk_err);
            Error {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "error while attempting to encrypt key".to_string(),
                details: "error while attempting to encrypt key".to_string(),
            }
        })?;

    let ciphertext = kms_res
        .ciphertext_blob()
        .ok_or(Error {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            message: "error while attempting to encrypt key".to_string(),
            details: "error while attempting to encrypt key".to_string(),
        })?;

    Ok(general_purpose::STANDARD.encode(ciphertext))
}


pub async fn decrypt<'config, 'event> (
    kms_client: &'config Client,
    kms_arn: &'config str,
    wrapped_dek: &'event str,
    resource_name: &'event str,
    perimeter_id: &'event Option<String>
) -> Result<String, Error> {
    let ciphertext = general_purpose::STANDARD.decode(wrapped_dek)
        .map_err(|b64_dec_err| {
            error!(target = "api:decrypt", "Base64 error while attempting to decrypt key: {:?}", &b64_dec_err);
            Error {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "error while attempting to encrypt key".to_string(),
                details: "error while attempting to encrypt key".to_string(),
            }
        })?;

    let mut kms_req = kms_client
        .decrypt()
        .key_id(kms_arn)
        .ciphertext_blob(Blob::new(ciphertext))
        .encryption_context("resource_name", resource_name);

    if perimeter_id.is_some() {
        let pid = perimeter_id.as_ref().unwrap();
        kms_req = kms_req.encryption_context("perimeter_id", pid) 
    }

    let kms_res = kms_req
        .send()
        .await
        .map_err(|sdk_err| {
            error!(target = "api:decrypt", "KMS error while attempting to decrypt key: {:?}", &sdk_err);
            Error {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "error while attempting to decrypt key".to_string(),
                details: "error while attempting to decrypt key".to_string(),
            }
        })?;

    let dek = kms_res
        .plaintext()
        .ok_or(Error {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            message: "error while attempting to decrypt key".to_string(),
            details: "error while attempting to decrypt key".to_string(),
        })?;
        //into_inner();

    Ok(general_purpose::STANDARD.encode(dek))
}
