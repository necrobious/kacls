use lambda_http::{
    Body,
    Request,
    Response,
    Error as LambdaHttpError,
};
use crate::v20230102::{
    config::Config,
    error::Error,
};
use serde_derive::{ Deserialize, Serialize };

use http::{
    status::StatusCode,
    header::CONTENT_TYPE,
};

use tracing::info;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct StatusResponse {
    name: String,
    vendor_id: String,
    version: String,
    server_type: String,
}

impl TryFrom<StatusResponse> for Response<Body> {
    type Error = LambdaHttpError;

    fn try_from(resp: StatusResponse) -> Result<Self, Self::Error> {
        let body = serde_json::to_string(&resp)
            .map(|s| Body::Text(s.to_string())) 
            .map_err(Box::new)?;

        let resp = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .status(StatusCode::OK)
            .body(body)
            .map_err(Box::new)?;

        Ok(resp)
    }
}

pub async fn status(_config: &Config, _event: Request) -> Result<StatusResponse, Error> {
    info!(target:"api:status", "/status route invoked");
    Ok(StatusResponse {
        name: "kacls".to_string(),
        vendor_id: "kacls.com".to_string(),
        version: "20230102".to_string(),
        server_type: "KACLS".to_string(),
    })
}
