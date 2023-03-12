use crate::v20230102::{
    Config,
    Error,
    status::status,
    wrap::wrap,
    unwrap::unwrap,
    digest::digest,
    rewrap::rewrap,
};
use http::{
    status::StatusCode,
    method::Method,
};
use lambda_http::{
    Body,
    Request,
    Response,
    Error as LambdaHttpError,
};

pub async fn route_request(config: &Config, event: Request) -> Result<Response<Body>, LambdaHttpError> {

    // info!("Event received: {:?}", &event);

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

    else if Method::POST == method && "/v20230102/rewrap" == path {
        return rewrap(&config, event).await.map_or_else(
            Response::try_from,
            Response::try_from
        )
    }
// /v20230102/takeout_unwrap

    else {
        let not_found = Error {
            code: StatusCode::NOT_FOUND,
            message: format!("unknown route: {}", &path),
            details: format!("unknown route: {}", &path),
        };

        Response::try_from(not_found)
    }

}


