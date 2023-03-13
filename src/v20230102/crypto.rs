use base64::{Engine as _, engine::general_purpose};
use crate::v20230102::error::Error;
use aws_sdk_kms::{ Client, types::Blob };
use ring;
use http::{ status::StatusCode };
use tracing::{ error };
use serde_derive::{ Serialize, Deserialize };
use serde_asn1_der;//::{ to_vec, from_bytes };

pub use base64::DecodeError;




#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct EncryptionPayload {
    //#[serde(with = "serde_bytes")]
    dek: Vec<u8>,
    resource_name: String,
    perimeter_id: Option<String>,
}

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    general_purpose::STANDARD.encode(input)
}
pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    general_purpose::STANDARD.decode(input)
}

pub async fn encrypt<'config, 'event> (
    // AWS SDK KMS Client to connect to the KMS service with
    kms_client: &'config Client,
    // AWS KMS CMK ARN to encrypt the DEK with
    kms_arn: &'config str,
    // The Data Encryption Key (DEK). Max size: 128 bytes.
    dek: &'event [u8],
    // An identifier for the object encrypted by the DEK. Maximum size: 128 bytes.
    resource_name: &'event str,
    // (Optional) A value tied to the document location that can be used to choose which perimeter will be checked when unwrapping. Maximum size: 128 bytes.
    perimeter_id: &'event Option<String>
) -> Result<Vec<u8>, Error> {

    let payload = EncryptionPayload {
        dek: dek.to_vec(),
        resource_name: resource_name.to_string(),
        perimeter_id: perimeter_id.clone(),
    };

    let payload_bytes = serde_asn1_der::to_vec(&payload).map_err(|der_err| {
        error!(target = "api:encrypt", "ASN.1 encoding error while attempting to encrypt key: {:?}", &der_err);
        Error {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            message: "error while attempting to encrypt key".to_string(),
            details: "error while attempting to encrypt key".to_string(),
        }
    })?;

    let kms_req = kms_client
        .encrypt()
        .key_id(kms_arn)
        .plaintext(Blob::new(payload_bytes));

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

    Ok(ciphertext.as_ref().into())
}

pub async fn decrypt<'config, 'event> (
    kms_client: &'config Client,
    kms_arn: &'config str,
    ciphertext: &'event [u8],
    resource_name: &'event str,
    perimeter_id: &'event Option<String>
) -> Result<Vec<u8>, Error> {

    let kms_req = kms_client
        .decrypt()
        .key_id(kms_arn)
        .ciphertext_blob(Blob::new(ciphertext));

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

    let payload_bytes = kms_res
        .plaintext()
        .ok_or(Error {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            message: "error while attempting to decrypt key".to_string(),
            details: "error while attempting to decrypt key".to_string(),
        })?;

    let payload: EncryptionPayload = serde_asn1_der::from_bytes(payload_bytes.as_ref()).map_err(|der_err| {
            error!(target = "api:decrypt", "ASN.1 error while attempting to decrypt key: {:?}", &der_err);
            Error {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "error while attempting to decrypt key".to_string(),
                details: "error while attempting to decrypt key".to_string(),
            }
        })?;

    if payload.resource_name != resource_name {
        return Err(Error {
            code: StatusCode::FORBIDDEN,
            message: "The provided resource_name is not authorized".into(),
            details: "The given resource_name id not authorized to view this key".into(),
        });
    }

    if payload.perimeter_id.is_some() && payload.perimeter_id != *perimeter_id {
        return Err(Error {
            code: StatusCode::FORBIDDEN,
            message: "The provided resource_name is not authorized at this perimeter".into(),
            details: "The given resource_name id not authorized to view this key at this perimeter".into(),
        });
    }

    Ok(payload.dek)
}

pub fn checksum<'event> (
    dek: &'event [u8],
    resource_name: &'event str,
) -> Vec<u8> {
    // TODO: cleanup allocs here, this is sloppy
    let mut prefix_bytes: Vec<u8> = "KACLMigration".as_bytes().into();
    let mut resource_bytes: Vec<u8> = resource_name.as_bytes().into();
    let mut dek_bytes: Vec<u8> = dek.into();
    let mut accum: Vec<u8> = Vec::with_capacity(prefix_bytes.len()+resource_bytes.len()+dek_bytes.len());
    accum.append(&mut prefix_bytes);
    accum.append(&mut resource_bytes);
    accum.append(&mut dek_bytes);

    let checksum = ring::digest::digest(&ring::digest::SHA256, &accum);
    checksum.as_ref().into()
}
