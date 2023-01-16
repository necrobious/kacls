use serde::ser::{Serialize, SerializeStruct, Serializer};
use http::{
    status::StatusCode,
    header::CONTENT_TYPE,
};


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
/*
pub type ResponseFuture = std::pin::Pin<Box<dyn std::future::Future<Output = lambda_http::Response<lambda_http::Body>> + Send>>;
impl lambda_http::IntoResponse for Error {
    fn into_response(self) -> ResponseFuture {
        Box::pin(async move {
            lambda_http::Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .status(self.code)
                .body(
                    serde_json::to_string(&self)
                        .expect("unable to serialize serde_json::Value")
                        .into(),
                )
                .expect("unable to build http::Response")
        })
    }
}
*/
impl TryFrom<Error> for lambda_http::Response<lambda_http::Body> {
    type Error = lambda_http::Error;

    fn try_from(e: Error) -> Result<Self, Self::Error> {
        let status = e.code;
        let body = serde_json::to_string(&e)
            .map(|s|lambda_http::Body::Text(s.to_string())) 
            .map_err(Box::new)?;

        let resp = lambda_http::Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .status(status)
            .body(body)
            .map_err(Box::new)?;

        Ok(resp)
    }
}
/*
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
*/
