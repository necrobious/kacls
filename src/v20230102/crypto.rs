use base64::{Engine as _, engine::general_purpose};
use crate::v20230102::error::Error;
use aws_sdk_kms::{ Client, types::Blob };

use http::{ status::StatusCode };

use tracing::{ error };
//use regex;

//const REGEX: &'static str: r"arn:aws:kms:(?P<region>(?:us|eu)-(?:east|west)-[0-9]):(?P<account>[0-9]{12}):key/(?P<key_id>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89ABab][a-fA-F0-9]{3}-[a-fA-F0-9]{12}|mrk-[a-fA-F0-9]{32})";

//const REGEX: &'static str: r"arn:aws:kms:(?P<region>(?:us|eu)-(?:east|west)-[0-9]):(?P<account>[0-9]{12}):key/(?P<key_id>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[abAB89][a-fA-F0-9]{3}-[a-fA-F0-9]{12}|mrk-[a-fA-F0-9]{32})";
pub async fn encrypt<'config, 'event> (
    kms_client: &'config Client,
    kms_arn: &'config str,
    dek: &'event str,
    resource_name: &'event str,
    perimeter_id: &'event Option<String>
) -> Result<String, Error> {

    let mut kms_req = kms_client
        .encrypt()
        .key_id(kms_arn)
        .plaintext(Blob::new(dek.as_bytes()))
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
        //into_inner();

    Ok(general_purpose::URL_SAFE_NO_PAD.encode(ciphertext))
}
