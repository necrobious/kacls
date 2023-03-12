mod https;
mod jwks;
mod v20230102;

use lambda_http::{
    Error as LambdaHttpError,
};
use http::{
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
    config::Config,
    auth::KaclsApiAuthorizationPolicy,
    keyid::KeyIndex,
    routes::route_request,
};

use ring::rand::SystemRandom;
use aws_sdk_kms as kms;

use tracing::info;
use serde_json;

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

    let kms_key_arns: Vec<String> = serde_json::from_str(
        &std::env::var("KACLS_ENC_KEY_ARNS").map_err(Box::new)?
    ).map_err(Box::new)?;

    info!("kms_key_arns: {:?}", &kms_key_arns);

    // first key in the list is the key we'll use to encrypt this run
    let kms_enc_arn = kms_key_arns[0].clone();
    let kms_key_idx = KeyIndex::from(kms_key_arns);
    info!("kms_key_idx: {}", &kms_key_idx.to_string());


    info!("collecting Google Client-Side Encryption JWKS");
    let http = https::build_https_client();

    let mut keys = jwks::fetch_jwks(&http, jwks::GOOGLE_CSE_KEYS).await.map_err(Box::new)?;
    let tst = serde_json::from_str::<jsonwebtoken::jwk::Jwk>(TEST_KEY).map_err(Box::new)?;
    keys.keys.push(tst);

    let authorization_policy = KaclsApiAuthorizationPolicy::new(vec!(
        "https://api.kacls.com/v20230102".into(),
//        "https://us-1.api.kacls.com/v20230102".into(),
    ));

    //let kms_arns = vec!(kms_arn);

    let config = Config {
        random: sysrand,
        authorization_policy,
        kms_client,
        kms_enc_arn,
        kms_key_idx,
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

