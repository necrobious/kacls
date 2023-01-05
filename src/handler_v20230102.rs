mod https;
mod jwks;
mod v20230102;

use lazy_static::lazy_static;
use lambda_runtime::{run, service_fn, LambdaEvent, Error as LambdaError};
use http::status::StatusCode;

use v20230102::{
    status::status,
    wrap::wrap,
    config::Config,
    error::Error,
};

use ring::rand::SystemRandom;
use aws_sdk_kms as kms;

use tracing::info;
use aws_lambda_events::{
    apigw::{ ApiGatewayV2httpRequest, ApiGatewayV2httpResponse },
};

lazy_static! {
    static ref ROUTE_STATUS: Option<String> = Some("GET /v20230102/status".to_string());
    static ref ROUTE_TAKEOUT_UNWRAP: Option<String> = Some("POST /v20230102/takeout_unwrap".to_string());
    static ref ROUTE_DIGEST: Option<String> = Some("POST /v20230102/digest".to_string());
    static ref ROUTE_REWRAP: Option<String> = Some("POST /v20230102/rewarp".to_string());
    static ref ROUTE_UNWRAP: Option<String> = Some("POST /v20230102/unwarp".to_string());
    static ref ROUTE_WRAP: Option<String> = Some("POST /v20230102/wrap".to_string());
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

    run(service_fn(|event: LambdaEvent<ApiGatewayV2httpRequest>| async {
        let route_key = event.payload.route_key.clone();

        if *ROUTE_STATUS == route_key {
            return status(&config, event).await.map_or_else(
                ApiGatewayV2httpResponse::try_from,
                ApiGatewayV2httpResponse::try_from
            )
        }
        else if *ROUTE_WRAP == route_key {
            return wrap(&config, event).await.map_or_else(
                ApiGatewayV2httpResponse::try_from,
                ApiGatewayV2httpResponse::try_from,
            )
        }
        else {
            let route = route_key.unwrap_or("<undefined>".to_string());
            info!(target:"app", "unknown route invoked: {}", &route);
            let not_found = Error {
                code: StatusCode::NOT_FOUND,
                message: format!("unknown route: {}", &route),
                details: format!("unknown route: {}", &route),
            };

            let resp = ApiGatewayV2httpResponse::try_from(not_found)?;
            Result::<ApiGatewayV2httpResponse, LambdaError>::Ok(resp)
        }
    })).await?;

    Ok(())
}
