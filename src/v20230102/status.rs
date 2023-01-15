use lambda_runtime::{LambdaEvent, Error as LambdaError};

use crate::v20230102::{
    config::Config,
    error::Error,
    http::{ CONTENT_TYPE, APPLICATION_JSON }
};
//use serde_json::{json, Value};
use serde_derive::{Deserialize,Serialize};
use aws_lambda_events::{
    encodings::Body,
    apigw::{ ApiGatewayV2httpRequest, ApiGatewayV2httpResponse },
    alb::{ AlbTargetGroupRequest, AlbTargetGroupResponse },
};
use http::{
    header::{ HeaderMap, HeaderName, HeaderValue },
    status::StatusCode,
};

use tracing::{ info, error };

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct StatusResponse {
    name: String,
    vendor_id: String,
    version: String,
    server_type: String,
}

//impl TryFrom<StatusResponse> for ApiGatewayV2httpResponse {
impl TryFrom<StatusResponse> for AlbTargetGroupResponse {
    type Error = LambdaError;
    fn try_from(e: StatusResponse) -> Result<Self, Self::Error> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(CONTENT_TYPE),
            HeaderValue::from_static(APPLICATION_JSON)
        );
        let body = serde_json::to_string(&e)?;
        //let resp = ApiGatewayV2httpResponse {
        let resp = AlbTargetGroupResponse {
            body: Some(Body::Text(body)),
            status_code: StatusCode::OK.as_u16().into(),
            status_description: Some("OK".into()),
            headers: headers, 
            //is_base64_encoded: Some(false),
            is_base64_encoded: false,
            ..Default::default()
        };
        Ok(resp)
    }
}

//pub async fn status(config: &Config, event: LambdaEvent<ApiGatewayV2httpRequest>) -> Result<StatusResponse, Error> {
pub async fn status(config: &Config, event: LambdaEvent<AlbTargetGroupRequest>) -> Result<StatusResponse, Error> {
    info!(target:"api:status", "/status route invoked");
    Ok(StatusResponse {
        name: "kacls".to_string(),
        vendor_id: "kacls.com".to_string(),
        version: "20230102".to_string(),
        server_type: "KACLS".to_string(),
    })
}
