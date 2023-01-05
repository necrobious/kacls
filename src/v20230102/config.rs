//use serde_derive::{Deserialize,Serialize};
//use serde::ser::{Serialize, SerializeStruct, Serializer};
//use serde_json::Value;
use ring::rand::SystemRandom;
use aws_sdk_kms::Client;
use jsonwebtoken::jwk::JwkSet;
/*
use http::{
    header::{ HeaderMap, HeaderName, HeaderValue },
    status::StatusCode,
};

use aws_lambda_events::{
    encodings::Body,
    apigw::{ ApiGatewayV2httpRequest, ApiGatewayV2httpResponse },
};
 
use lambda_runtime::{ Error as LambdaError };
*/
#[derive(Clone, Debug)]
pub struct Config {
    pub random: SystemRandom,
    pub kms_client: Client,
    pub trusted_keys: JwkSet,
}

