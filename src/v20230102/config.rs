use ring::rand::SystemRandom;
use aws_sdk_kms::Client;
use jsonwebtoken::jwk::JwkSet;
use crate::v20230102::KaclsApiAuthorizationPolicy;

#[derive(Clone, Debug)]
pub struct Config {
    pub random: SystemRandom,
    pub kms_client: Client,
    pub kms_arns: Vec<String>,
    pub authorization_policy: KaclsApiAuthorizationPolicy,
    pub trusted_keys: JwkSet,
}

