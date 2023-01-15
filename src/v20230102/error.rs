//use serde_derive::{Deserialize,Serialize};
use serde::ser::{Serialize, SerializeStruct, Serializer};
//use serde_json::Value;
//use ring::rand::SystemRandom;
//use aws_sdk_kms::Client;
//use jsonwebtoken::jwk::JwkSet;
use http::{
    header::{ HeaderMap, HeaderName, HeaderValue },
    status::StatusCode,
};

use crate::v20230102::http::{ CONTENT_TYPE, APPLICATION_JSON };

use aws_lambda_events::{
    encodings::Body,
    apigw::ApiGatewayV2httpResponse,
    alb::AlbTargetGroupResponse,
};
 
use lambda_runtime::{ Error as LambdaError };
use tracing::error; 

//
// https://developers.google.com/workspace/cse/reference/structured-errors
// 
#[derive(Debug, Clone, PartialEq)] //, Deserialize, Serialize)]
pub struct Error {
    pub code: StatusCode,
    pub message: String,
    pub details: String,
}

// StatusCode doesnt implement Serialize 😤
impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut err = serializer.serialize_struct("Error", 3)?;
        err.serialize_field("code", &self.code.as_u16())?;
        err.serialize_field("message", &self.message)?;
        err.serialize_field("details", &self.details)?;
        err.end()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error code: {}; message: {}, details: {}", &self.code, &self.message, &self.details)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

//impl TryFrom<Error> for ApiGatewayV2httpResponse {
impl TryFrom<Error> for AlbTargetGroupResponse {
    type Error = LambdaError;

    fn try_from(e: Error) -> Result<Self, Self::Error> {
        error!("try_from Error: {}", &e);
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(CONTENT_TYPE),
            HeaderValue::from_static(APPLICATION_JSON)
        );
        let body = serde_json::to_string(&e)?;
        //let resp = ApiGatewayV2httpResponse {
        let resp = AlbTargetGroupResponse {
            body: Some(Body::Text(body)),
            status_code: e.code.clone().as_u16().into(),
            status_description: e.code.canonical_reason().map(|s| s.to_string()),
            headers: headers, 
            //is_base64_encoded: Some(false),
            is_base64_encoded: false,
            ..Default::default()
        };
        Ok(resp)
    }
}

