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
    unwrap::unwrap,
    digest::digest,
    config::Config,
    error::Error,
    auth::KaclsApiAuthorizationPolicy,
};

use ring::rand::SystemRandom;
use aws_sdk_kms as kms;

use tracing::info;

const TEST_KEY: &'static str = r#"
{
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "test-key-42",
    "alg": "RS256",
    "n": "lAa-Ldkrhc4hrT02ZF6PcHiq2SNbb_U-QZKXVoV-w1oyv8LBJWiDDHcrwYiMbE1R-sK5Qoksvc2B6Q0ufwcRkTKuIA4RT56CBTPVL25eMCjc-pIcRABl_rIEFs3Mgj0KEOMlk2J4SrlVT5rDVfgV3tgjs9cjh9vB_RZgGwFmRcxpc-qcdOg-zrB3dxP-VEGGKjchOBRD65sHJRxURl7Xtyr4bYkzq1-F6u-A0j1iES5Aji-5DTkcJ3gZKtzXGqDnMhL97KT9HBPdLhMqLCiSnDSyWiyPPGsz0uls8RT31dbWCLf-A1nNFtmtYuvpWdD6ywAveGC8HXAXW_iW8zfkiw"
}
"#;

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

    else if Method::POST == method && "/v20230102/unwrap" == path {
        return unwrap(&config, event).await.map_or_else(
            Response::try_from,
            Response::try_from
        )
    }

    else if Method::POST == method && "/v20230102/digest" == path {
        return digest(&config, event).await.map_or_else(
            Response::try_from,
            Response::try_from
        )
    }
// /v20230102/takeout_unwrap
// /v20230102/rewarp

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

    let kms_arn = std::env::var("KACLS_ENC_KEY_ARN").map_err(Box::new)?;

    info!("collecting Google Client-Side Encryption JWKS");
    let http = https::build_https_client();

    let mut keys = jwks::fetch_jwks(&http, jwks::GOOGLE_CSE_KEYS).await.map_err(Box::new)?;
    let tst = serde_json::from_str::<jsonwebtoken::jwk::Jwk>(TEST_KEY).map_err(Box::new)?;
    keys.keys.push(tst);

    let authorization_policy = KaclsApiAuthorizationPolicy::new(vec!(
        "https://api.kacls.com/v20230102".into(),
//        "https://us-1.api.kacls.com/v20230102".into(),
    ));

    let kms_arns = vec!(kms_arn);

    let config = Config {
        random: sysrand,
        authorization_policy,
        kms_client,
        kms_arns,
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

