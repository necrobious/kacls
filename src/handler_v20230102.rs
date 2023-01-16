mod https;
mod jwks;
mod v20230102;


use lambda_http::{
    Body,
    Request,
    Response,
    Error as LambdaHttpError,
};
use http::{
    status::StatusCode,
    method::Method,
    header::{
        HeaderValue,
        STRICT_TRANSPORT_SECURITY,
        CONTENT_SECURITY_POLICY,
        X_CONTENT_TYPE_OPTIONS,
        X_FRAME_OPTIONS,
        X_XSS_PROTECTION,
    },
};

use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    set_header::SetResponseHeaderLayer,
    trace::{ DefaultOnRequest, DefaultOnResponse, TraceLayer },
};

use v20230102::{
    status::status,
    wrap::wrap,
    config::Config,
    error::Error,
};

use ring::rand::SystemRandom;
use aws_sdk_kms as kms;

use tracing::info;

async fn route_request(
    config: &Config,
    event: Request) -> Result<Response<Body>, LambdaHttpError> {

    info!("Event received: {:?}", &event);

    let method = event.method();
    let path = event.uri().path();

    if Method::GET == method && "/healthcheck" == path {
        let resp = Response::builder()
            .status(204)
            .body(lambda_http::Body::Empty)?;
        Ok(resp)
    }

    else if Method::GET == method && "/v20230102/status" == path {
        return status(&config, event).await.map_or_else(
            Response::try_from,
            Response::try_from
        )
    }

    else if Method::POST == method && "/v20230102/wrap" == path {
        return wrap(&config, event).await.map_or_else(
            Response::try_from,
            Response::try_from
        )
    }
// /v20230102/takeout_unwrap
// /v20230102/digest
// /v20230102/rewarp
// /v20230102/unwarp

    else {
        let not_found = Error {
            code: StatusCode::NOT_FOUND,
            message: format!("unknown route: {}", &path),
            details: format!("unknown route: {}", &path),
        };

        Response::try_from(not_found)
    }

}

#[tokio::main]
async fn main() -> Result<(), LambdaHttpError> {
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
    let keys = jwks::fetch_jwks(&http, jwks::GOOGLE_CSE_KEYS).await.map_err(Box::new)?;

    let config = Config {
        random: sysrand,
        kms_client,
        trusted_keys: keys,
    };
    
//--- security headers 
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST
        ])
        .allow_origin([
            "https://client-side-encryption.google.com".parse().unwrap(),
        ]);
    let sts = SetResponseHeaderLayer::overriding(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubdomains; preload")
    );
    let csp = SetResponseHeaderLayer::overriding(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'")
    );
    let cto = SetResponseHeaderLayer::overriding(
        X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff")
    );
    let fro = SetResponseHeaderLayer::overriding(
        X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY")
    );
    let xss = SetResponseHeaderLayer::overriding(
        X_XSS_PROTECTION,
        HeaderValue::from_static("1; mode=block")
    );

//--- request/response tracing
    let trace = TraceLayer::new_for_http()
        .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
        .on_response(DefaultOnResponse::new().level(tracing::Level::INFO));

//---
    let service = ServiceBuilder::new()
        .layer(trace)
        .layer(cors)
        .layer(sts)
        .layer(csp)
        .layer(cto)
        .layer(fro)
        .layer(xss)
        .service_fn(|event: lambda_http::Request| async {
            route_request(&config, event).await
        });
    lambda_http::run(service).await
}

/*
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
    .allow_methods([Method::GET, Method::POST])
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
*/
