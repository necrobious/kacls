use crate::https::{ Client };
use http;
use jsonwebtoken;
use serde_json;

pub const GOOGLE_CSE_KEYS: &'static str = "https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-drive@system.gserviceaccount.com";

#[derive(Debug)]
pub enum Error {
    // THe request failed to compile into a valid hyper Request instance
    MalformedRequest(http::Error),
    // The attempt to connect to the JWKS endpoint failed, we were not able to get a cconnection,
    // or the response wasnt a valid https protocal response
    NetworkRequest(hyper::Error),
    // The JWKS endpoint returned a valid http response, but the status code was not the expected
    // 200 Ok response.
    ResponseError(http::Response<hyper::Body>), 
    // The response was valid, and returned a 200 Ok response, however they reponse body is either
    // unavailable or invalid bytes
    InvalidResponseBody(<hyper::Body as hyper::body::HttpBody>::Error),
    // The response was a valid HTTP 200 Ok Response, however the response body contained bytes
    // thatdid not decode into the expected UTF-8 string data that all valid JSON must conform to.
    InvalidUtf8Response(std::string::FromUtf8Error),
    // The response was a valid HTTP 200 Ok Response, and contained valid UTF-8 string data,
    // however the string data failed to parse into a valid JwkSet instance, either because the
    // string data was invalid JSON, or because it was valid JSON that did not conform to the
    // expected JWKS JSON schema.
    InvalidJwksResponse(serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MalformedRequest(e) => write!(f, "MalformedRequest: {:?}", e), 
            Error::NetworkRequest(e) => write!(f, "NetworkRequest: {:?}", e), 
            Error::ResponseError(e) => write!(f, "ResponseError: {:?}", e),
            Error::InvalidJwksResponse(e) => write!(f, "InvalidJwksResponse: {:?}", e),
            Error::InvalidUtf8Response(e) => write!(f, "InvalidUtf8Response: {:?}", e),
            Error::InvalidResponseBody(e) => write!(f, "InvalidResponseBody: {:?}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::MalformedRequest(e) => Some(e),
            Error::NetworkRequest(e) => Some(e),
            Error::ResponseError(_) => None,
            Error::InvalidJwksResponse(e) => Some(e), 
            Error::InvalidUtf8Response(e) => Some(e),
            Error::InvalidResponseBody(e) => Some(e),
        }
    }
}

/// Uses the given client to attempt an https call to the given Json Web Key Set (jwks) OIDC
/// endpoint to retrieve a JWKS response, an deserialize them into a JwkSet instance.
/// Note retrying is not attempted here, exactly one attempt will be made, retry attepts should be
/// handled by the caller.
pub async fn fetch_jwks <'client, 'url> (client: &'client Client, jwks_url: &'url str) -> Result<jsonwebtoken::jwk::JwkSet, Error> {
    let req: hyper::Request<hyper::Body> = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(jwks_url)
        .header("content-type", "application/json")
        .body(hyper::Body::from(vec!()))
        .map_err(Error::MalformedRequest)?;
    client
        .request(req)
        .await
        .map_err(Error::NetworkRequest)
        .and_then(|resp| 
            if resp.status() != hyper::StatusCode::OK {
                Err(Error::ResponseError(resp))
            } else {
                Ok(resp)
            }
        )
        .map(|resp| hyper::body::to_bytes(resp.into_body()))?
        .await
        .map_err(|e| Error::InvalidResponseBody(e))
        .and_then(|bytes|
            String::from_utf8(bytes.to_vec()).map_err(|e| Error::InvalidUtf8Response(e)))
        .and_then(|string_resp|
            serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(&string_resp).map_err(|e| Error::InvalidJwksResponse(e)))
}


#[cfg(test)]
mod tests {
    use crate::https;
    use crate::jwks;
    use tokio_test::block_on;

    #[test]
    fn retrieve_google_cse_jwks_should_succeed () {
        let http = https::build_https_client();
        let keys = block_on( jwks::fetch_jwks(&http, jwks::GOOGLE_CSE_KEYS) );

        assert!(keys.is_ok());
    }

    #[test]
    fn invalid_url_should_fail () {
        
        let http = https::build_https_client();
        let keys = block_on( jwks::fetch_jwks(&http, "im not a url") );

        assert!(keys.is_err());
        match keys.unwrap_err() {
            jwks::Error::MalformedRequest(_) => (),
            something_else @ _ => panic!("expected a MalformedRequest(_) instance got: {:?}", something_else)
        }
    }
}
