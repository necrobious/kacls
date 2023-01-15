mod https;
mod jwks;
mod v20230102;

use lazy_static::lazy_static;
use lambda_runtime::{run, service_fn, LambdaEvent, Error as LambdaError};
use http::{
    status::StatusCode,
    method::Method,
    header::{ HeaderMap, HeaderName, HeaderValue },
};

use tower::{ServiceBuilder, ServiceExt, Service};
use tower_http::cors::{Any, CorsLayer};

use v20230102::{
    status::status,
    wrap::wrap,
    config::Config,
    error::Error,
    http::{ CONTENT_TYPE, TEXT_HTML }
};

use ring::rand::SystemRandom;
use aws_sdk_kms as kms;

use tracing::info;
use aws_lambda_events::{
    encodings::Body,
    apigw::{ ApiGatewayV2httpRequest, ApiGatewayV2httpResponse },
    alb::{ AlbTargetGroupRequest, AlbTargetGroupResponse },
};

lazy_static! {
    //static ref ROUTE_STATUS: Option<String> = Some("GET /v20230102/status".to_string());
    //static ref ROUTE_TAKEOUT_UNWRAP: Option<String> = Some("POST /v20230102/takeout_unwrap".to_string());
    //static ref ROUTE_DIGEST: Option<String> = Some("POST /v20230102/digest".to_string());
    //static ref ROUTE_REWRAP: Option<String> = Some("POST /v20230102/rewarp".to_string());
    //static ref ROUTE_UNWRAP: Option<String> = Some("POST /v20230102/unwarp".to_string());
    //static ref ROUTE_WRAP: Option<String> = Some("POST /v20230102/wrap".to_string());

    static ref PATH_HEALTH_CHECK: Option<String> = Some("/healthcheck".into());
    static ref PATH_STATUS: Option<String> = Some("/v20230102/status".into());
    static ref PATH_TAKEOUT_UNWRAP: Option<String> = Some("/v20230102/takeout_unwrap".into());
    static ref PATH_DIGEST: Option<String> = Some("/v20230102/digest".into());
    static ref PATH_REWRAP: Option<String> = Some("/v20230102/rewarp".into());
    static ref PATH_UNWRAP: Option<String> = Some("/v20230102/unwarp".into());
    static ref PATH_WRAP: Option<String> = Some("/v20230102/wrap".into());
    
}

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    let sysrand = SystemRandom::new();

    let aws_config = aws_config::from_env().load().await;
    let kms_client = kms::Client::new(&aws_config);

    info!("collecting Google Client-Side Encryption JWKS");
    let http = https::build_https_client();
    let keys = jwks::fetch_jwks(&http, jwks::GOOGLE_CSE_KEYS).await.map_err(|e| LambdaError::from(e))?;

    let config = Config {
        random: sysrand,
        kms_client,
        trusted_keys: keys,
    };

    //run(service_fn(|event: LambdaEvent<ApiGatewayV2httpRequest>| async {
//    run(service_fn(|event: LambdaEvent<AlbTargetGroupRequest>| async {

    let cors = CorsLayer::new()
    // allow `GET` and `POST` when accessing the resource
    .allow_methods([Method::GET, Method::POST])
    // allow requests from any origin
    .allow_origin(Any);

//    run(ServiceBuilder::new().layer(cors).service_fn(|event: LambdaEvent<AlbTargetGroupRequest>| async {
    run(ServiceBuilder::new().service_fn(|event: LambdaEvent<AlbTargetGroupRequest>| async {
//        let route_key = event.payload.route_key.clone();

        info!("Event received: {:?}", &event);

        let method = event.payload.http_method.clone();
        let path = event.payload.path.clone();

        if Method::GET == method && *PATH_HEALTH_CHECK == path {
            info!("Health check route matched");
            //let mut headers = HeaderMap::new();
            //headers.insert(
            //    HeaderName::from_static(CONTENT_TYPE),
            //    HeaderValue::from_static(TEXT_HTML)
            //);

            return Ok(AlbTargetGroupResponse {
                body: None, // Some(Body::Text("Ok".into())),
                status_code: 204,
                status_description: Some("No Content".into()),
                is_base64_encoded: false,
            //    headers: headers, 
                ..Default::default()
            })
        }
        else if Method::GET == method && *PATH_STATUS == path {
            info!("status route matched");
            return status(&config, event).await.map_or_else(
                AlbTargetGroupResponse::try_from,
                AlbTargetGroupResponse::try_from
                //ApiGatewayV2httpResponse::try_from,
                //ApiGatewayV2httpResponse::try_from
            )
        }
        else if Method::POST == method && *PATH_WRAP == path {
            return wrap(&config, event).await.map_or_else(
                AlbTargetGroupResponse::try_from,
                AlbTargetGroupResponse::try_from,
                //ApiGatewayV2httpResponse::try_from,
                //ApiGatewayV2httpResponse::try_from,
            )
        }
        else {
            //let route = route_key.unwrap_or("<undefined>".to_string());
            let route = path.unwrap_or("<undefined>".to_string());
            info!(target:"app", "unknown route invoked: {}", &route);
            let not_found = Error {
                code: StatusCode::NOT_FOUND,
                message: format!("unknown route: {}", &route),
                details: format!("unknown route: {}", &route),
            };

            //let resp = ApiGatewayV2httpResponse::try_from(not_found)?;
            let resp = AlbTargetGroupResponse::try_from(not_found)?;
            //Result::<ApiGatewayV2httpResponse, LambdaError>::Ok(resp)
            Result::<AlbTargetGroupResponse, LambdaError>::Ok(resp)
        }
    })).await?;

    Ok(())
}
