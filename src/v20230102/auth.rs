use crate::v20230102::{
    error::Error
};
use http::{
    status::StatusCode,
};
use jsonwebtoken::{
    decode,
    decode_header,
    DecodingKey,
    Validation,
    jwk::{ AlgorithmParameters, JwkSet },
};

use tracing::{ info, error };
use serde_json::{json, Value, from_str, from_slice};
use serde_derive::{Deserialize,Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AuthenticationToken {
    aud: String,
    email: String,
    exp: String,
    iat: String,
    iss: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AuthorizationToken {
  aud: String,
  email: String,
  exp: String,
  iat: String,
  iss: String,
  kacls_url: String,
  perimeter_id: String,
  resource_name: String,
  role: String,
}

fn invalid_authz_token() -> Error {
    Error {
      code: StatusCode::FORBIDDEN,
      message: "Authorization token is not valid".to_string(),
      details: "Attempt to validate the included Authorization JWT failed".to_string(),
    }
}


fn invalid_authn_token() -> Error {
    Error {
      code: StatusCode::UNAUTHORIZED,
      message: "Authentication token is not valid".to_string(),
      details: "Attempt to validate the included Authentication JWT failed".to_string(),
    }
}

pub fn validate_authz_token <'keys, 'req> (trusted_keys: &'keys JwkSet, authorization_token: &'req str) -> Result<jsonwebtoken::TokenData<AuthorizationToken>, Error> {
    let header = decode_header(authorization_token).map_err(|e| {
        error!(target:"api:auth", "while attempting to decode the header of the Authorization JWT: {}", &e);    
        invalid_authz_token()
    })?;

    let kid = header.kid.ok_or_else(|| {
        error!(target:"api:auth", "missing expected `kid` claim in the header of the Authorization JWT");
        invalid_authz_token()
    })?;

    if let Some(trusted_key) = trusted_keys.find(&kid) {
        match trusted_key.algorithm {
            AlgorithmParameters::RSA(ref rsa) => {
                let decoding_key =
                    DecodingKey::from_rsa_components(&rsa.n, &rsa.e).map_err(|e| {
                        error!(
                            target:"api:auth",
                            "Attempt to construct Decoding Key instance for RSA key with `kid` {} failed: {}",
                            &kid,
                            &e
                        );    
                        invalid_authz_token()
                    })?;
                let mut validation =
                    Validation::new(trusted_key.common.algorithm.ok_or_else(|| {
                        error!(
                            target:"api:auth",
                            "Attempt to construct Validation instance for RSA key with `kid` {} failed.",
                            &kid
                        );    
                        invalid_authz_token()
                    })?);

                // TODO: aud check
                // TODO: iss check
                validation.validate_exp = false;

                decode::<AuthorizationToken>(authorization_token, &decoding_key, &validation).map_err(|e| {
                    error!(target:"api:auth", "Authorization JWT decode() failed: {}", &e);    
                    invalid_authz_token()
                })
            }
            _ => {
                error!(
                    target:"api:auth",
                    "trusted key key for `kid` claim {} in the header of the Authorization JWT is not the expected (RSA) algorithm, but rather {:?}",
                    &kid,
                    &trusted_key.algorithm
                );
                Err(invalid_authz_token())
            }
        }
    } else {
        error!(target:"api:auth", "no trusted key key for `kid` claim {} in the header of the Authorization JWT", &kid);    
        Err(invalid_authz_token())
    }
}


pub fn validate_authn_token <'keys, 'req> (trusted_keys: &'keys JwkSet, authentication_token: &'req str) -> Result<jsonwebtoken::TokenData<AuthenticationToken>, Error> {
    let header = decode_header(authentication_token).map_err(|e| {
        error!(target:"api:auth", "while attempting to decode the header of the Authentication JWT: {}", &e);    
        invalid_authn_token()
    })?;

    let kid = header.kid.ok_or_else(|| {
        error!(target:"api:auth", "missing expected `kid` claim in the header of the Authentication JWT");
        invalid_authn_token()
    })?;

    if let Some(trusted_key) = trusted_keys.find(&kid) {
        match trusted_key.algorithm {
            AlgorithmParameters::RSA(ref rsa) => {
                let decoding_key =
                    DecodingKey::from_rsa_components(&rsa.n, &rsa.e).map_err(|e| {
                        error!(
                            target:"api:auth",
                            "Attempt to construct Decoding Key instance for RSA key with `kid` {} failed: {}",
                            &kid,
                            &e
                        );    
                        invalid_authn_token()
                    })?;
                let mut validation =
                    Validation::new(trusted_key.common.algorithm.ok_or_else(|| {
                        error!(
                            target:"api:auth",
                            "Attempt to construct Validation instance for RSA key with `kid` {} failed.",
                            &kid
                        );    
                        invalid_authn_token()
                    })?);

                // TODO: aud check
                // TODO: iss check
                validation.validate_exp = false;

                //decode::<HashMap<String, serde_json::Value>>(authentication_token, &decoding_key, &validation)
                decode::<AuthenticationToken>(authentication_token, &decoding_key, &validation).map_err(|e| {
                    error!(target:"api:auth", "Authentication JWT decode() failed: {}", &e);    
                    invalid_authn_token()
                })
            }
            _ => {
                error!(
                    target:"api:auth",
                    "trusted key key for `kid` claim {} in the header of the Authentication JWT is not the expected (RSA) algorithm, but rather {:?}",
                    &kid,
                    &trusted_key.algorithm
                );
                Err(invalid_authn_token())
            }
        }
    } else {
        error!(target:"api:auth", "no trusted key key for `kid` claim {} in the header of the Authentication JWT", &kid);    
        Err(invalid_authn_token())
    }
}


