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

use tracing::{
//    info,
    error,
};

use serde_derive::{ Deserialize, Serialize };

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AuthenticationToken {
    pub aud: String,
    pub email: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
}

// Contains one of the follow values:
//
//    reader: Allowed to call unwrap only.
//    writer: Allowed to call both wrap and unwrap
//    upgrader: Allowed to call wrap only. This is used by Google servers when performing one-way conversion of plain-text objects to encrypted objects.
//
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationRole {
    Reader,
    Writer,
    Upgrader,
}

impl std::fmt::Display for AuthorizationRole {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            AuthorizationRole::Reader => write!(f, "reader"),
            AuthorizationRole::Writer => write!(f, "writer"),
            AuthorizationRole::Upgrader => write!(f, "upgrader"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AuthorizationToken {
    pub aud: String,
    pub email: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub kacls_url: String,
    pub perimeter_id: Option<String>,
    pub resource_name: String,
    pub role: AuthorizationRole,
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

#[derive(Clone, Debug)]
pub struct KaclsApiAuthorizationPolicy {
    expected_kacls_urls: Vec<String> 
}

impl KaclsApiAuthorizationPolicy {

    //replace with constant-time fn
    fn compare (lft: &str, rgt: &str) -> bool {
        lft.to_lowercase() == rgt.to_lowercase()
    }

    pub fn new(expected_kacls_urls: Vec<String>) -> KaclsApiAuthorizationPolicy {
        KaclsApiAuthorizationPolicy {
            expected_kacls_urls
        }
    }

    pub fn can_rewrap(&self, authz_token: &AuthorizationToken) -> Result<(), Error> {
        // Check that authorization and authentication tokens are for the same user by doing a case-insensitive match on the email claims.

        // Check that the role claim in the authorization token is "reader" or "writer", granting
        // the prermission to unwrap the DEK
        if authz_token.role != AuthorizationRole::Writer && authz_token.role != AuthorizationRole::Reader {
            error!(target:"api:rewrap", "authz role {} is not the expected 'role' values of 'reader' or 'writer'.", &authz_token.role);
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Rewrap request body did not contain an authorization token a valid role.".to_string(),
                details: "Expected the authorization token's role claim for the 'rewrap' action to match those listed in https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(),
            })
        }
        // Check that the kacls_url claim in the authorization token matches the current KACLS URL.
        // This check allows detection of potential man-in-the-middle servers configured by insiders or rogue domain administrators.
        if !self.expected_kacls_urls.contains(&authz_token.kacls_url) {
            error!(
                target:"api:rewrap",
                "authz kacls_url {} is not in the expected list of valid kacls_urls {:?}.",
                &authz_token.kacls_url,
                &self.expected_kacls_urls,
            );
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Rewrap request body did not contain an authorization token a valid kacls server.".to_string(),
                details: "Expected the authorization token's kacls_url claim for the 'rewrap' action to match those listed as valid for this server; see: https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(),
            })
        }
        Ok(())
    }


    pub fn can_digest(&self, authz_token: &AuthorizationToken) -> Result<(), Error> {
        // Check that authorization and authentication tokens are for the same user by doing a case-insensitive match on the email claims.

        // Check that the role claim in the authorization token is "reader" or "writer", granting
        // the prermission to unwrap the DEK
        if authz_token.role != AuthorizationRole::Writer && authz_token.role != AuthorizationRole::Reader {
            error!(target:"api:digest", "authz role {} is not the expected 'role' values of 'reader' or 'writer'.", &authz_token.role);
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Digest request body did not contain an authorization token a valid role.".to_string(),
                details: "Expected the authorization token's role claim for the 'digest' action to match those listed in https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(),
            })
        }
        // Check that the kacls_url claim in the authorization token matches the current KACLS URL.
        // This check allows detection of potential man-in-the-middle servers configured by insiders or rogue domain administrators.
        if !self.expected_kacls_urls.contains(&authz_token.kacls_url) {
            error!(
                target:"api:digest",
                "authz kacls_url {} is not in the expected list of valid kacls_urls {:?}.",
                &authz_token.kacls_url,
                &self.expected_kacls_urls,
            );
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Digest request body did not contain an authorization token a valid kacls server.".to_string(),
                details: "Expected the authorization token's kacls_url claim for the 'digest' action to match those listed as valid for this server; see: https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(),
            })
        }
        Ok(())
    }

    pub fn can_unwrap(&self, authn_token: &AuthenticationToken, authz_token: &AuthorizationToken) -> Result<(), Error> {
        // Check that authorization and authentication tokens are for the same user by doing a case-insensitive match on the email claims.
        if !KaclsApiAuthorizationPolicy::compare(
            &authn_token.email,
            &authz_token.email
        ) {
            error!(target:"api:unwrap", "authn email {} does not match authz email {}.", &authn_token.email, &authz_token.email);
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Unwrap request body did not contain a valid pair of authentication and authorization tokens for the 'unwrap' action.".to_string(),
                details: "Expected the authentication and authorization tokens email claims to match, as described in https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(), 
            })
        }
        // Check that the role claim in the authorization token is "reader" or "writer".
        if authz_token.role != AuthorizationRole::Writer && authz_token.role != AuthorizationRole::Reader {
            error!(target:"api:unwrap", "authz role {} is not the expected 'role' values of 'reader' or 'writer'.", &authz_token.role);
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Unwrap request body did not contain an authorization token a valid role.".to_string(),
                details: "Expected the authorization token's role claim for the 'unwrap' action to match those listed in https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(), 
            })
        }
        // Check that the kacls_url claim in the authorization token matches the current KACLS URL.
        // This check allows detection of potential man-in-the-middle servers configured by insiders or rogue domain administrators.
        if !self.expected_kacls_urls.contains(&authz_token.kacls_url) {
            error!(
                target:"api:unwrap",
                "authz kacls_url {} is not in the expected list of valid kacls_urls {:?}.",
                &authz_token.kacls_url,
                &self.expected_kacls_urls,
            );
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Unwrap request body did not contain an authorization token a valid kacls server.".to_string(),
                details: "Expected the authorization token's kacls_url claim for the 'unwrap' action to match those listed as valid for this server; see: https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(), 
            })
        }
        Ok(())
    }

    pub fn can_wrap(&self, authn_token: &AuthenticationToken, authz_token: &AuthorizationToken) -> Result<(), Error> {
        // Check that authorization and authentication tokens are for the same user by doing a case-insensitive match on the email claims.
        if !KaclsApiAuthorizationPolicy::compare(
            &authn_token.email,
            &authz_token.email
        ) {
            error!(target:"api:wrap", "authn email {} does not match authz email {}.", &authn_token.email, &authz_token.email);
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Wrap request body did not contain a valid pair of authentication and authorization tokens for the 'wrap' action.".to_string(),
                details: "Expected the authentication and authorization tokens email claims to match, as described in https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(), 
            })
        }
        // Check that the role claim in the authorization token is "writer" or "upgrader".
        if authz_token.role != AuthorizationRole::Writer && authz_token.role != AuthorizationRole::Upgrader {
            error!(target:"api:wrap", "authz role {} is not the expected 'role' values of 'writer' or 'upgrader'.", &authz_token.role);
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Wrap request body did not contain an authorization token a valid role.".to_string(),
                details: "Expected the authorization token's role claim for the 'wrap' action to match those listed in https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(), 
            })
        }

        // Check that the kacls_url claim in the authorization token matches the current KACLS URL.
        // This check allows detection of potential man-in-the-middle servers configured by insiders or rogue domain administrators.
        if !self.expected_kacls_urls.contains(&authz_token.kacls_url) {
            error!(
                target:"api:wrap",
                "authz kacls_url {} is not in the expected list of valid kacls_urls {:?}.",
                &authz_token.kacls_url,
                &self.expected_kacls_urls,
            );
            return Err(Error {
                code: StatusCode::FORBIDDEN,
                message: "Wrap request body did not contain an authorization token a valid kacls server.".to_string(),
                details: "Expected the authorization token's kacls_url claim for the 'wrap' action to match those listed as valid for this server; see: https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data".to_string(), 
            })
        }
        Ok(())
    }
}

