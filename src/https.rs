
pub type Client = hyper::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;
pub fn build_https_client() -> Client {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();

    let client: Client = hyper::Client::builder().build(https);
    client
}
