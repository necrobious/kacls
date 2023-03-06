use ring::rand::SystemRandom;
use aws_sdk_kms::Client;
use jsonwebtoken::jwk::JwkSet;
use crate::v20230102::KaclsApiAuthorizationPolicy;
use crate::v20230102::KeyIndex;

#[derive(Clone, Debug)]
pub struct Config {
    pub random: SystemRandom,
    pub kms_client: Client,
    pub kms_enc_arn: String,
    pub kms_key_idx: KeyIndex,
    pub authorization_policy: KaclsApiAuthorizationPolicy,
    pub trusted_keys: JwkSet,
}

