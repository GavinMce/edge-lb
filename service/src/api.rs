//! HTTP API + embedded web UI. Every `/api` call needs `Authorization: Bearer <token>`.
//! The token travels in a header (not a cookie), so cross-site requests can't ride on it.

use crate::config::Route;
use crate::engine::{Engine, EngineError};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

const INDEX: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub struct ApiError(EngineError);

impl From<EngineError> for ApiError {
    fn from(e: EngineError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match &self.0 {
            EngineError::NotFound(_) => (StatusCode::NOT_FOUND, json!({ "error": self.0.to_string() })),
            EngineError::Conflict(_) => (StatusCode::CONFLICT, json!({ "error": self.0.to_string() })),
            EngineError::Invalid(errs) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({ "error": "invalid route configuration", "details": errs }),
            ),
            EngineError::Internal(_) => {
                tracing::error!("{}", self.0);
                (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": self.0.to_string() }))
            }
        };
        (status, Json(body)).into_response()
    }
}

async fn auth(State(token): State<Arc<str>>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if bool::from(presented.as_bytes().ct_eq(token.as_bytes())) {
        return next.run(req).await;
    }
    tokio::time::sleep(Duration::from_millis(250)).await; // blunt online guessing
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "missing or invalid token" }))).into_response()
}

async fn status(State(e): State<Engine>) -> impl IntoResponse {
    Json(e.status().await)
}
async fn list(State(e): State<Engine>) -> impl IntoResponse {
    Json(e.list().await)
}
async fn get_one(State(e): State<Engine>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(e.get(&id).await?))
}
async fn create(State(e): State<Engine>, Json(r): Json<Route>) -> Result<impl IntoResponse, ApiError> {
    Ok((StatusCode::CREATED, Json(e.create(r).await?)))
}
async fn update(
    State(e): State<Engine>,
    Path(id): Path<String>,
    Json(r): Json<Route>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(e.update(&id, r).await?))
}
async fn delete(State(e): State<Engine>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    e.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn replace(State(e): State<Engine>, Json(rs): Json<Vec<Route>>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(e.replace_all(rs).await?))
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}

pub fn router(engine: Engine, token: Arc<str>) -> Router {
    let api = Router::new()
        .route("/status", get(status))
        .route("/routes", get(list).post(create).put(replace))
        .route("/routes/:id", get(get_one).put(update).delete(delete))
        .layer(middleware::from_fn_with_state(token, auth))
        .with_state(engine);

    Router::new()
        .route("/", get(|| async { asset("text/html; charset=utf-8", INDEX) }))
        .route("/app.js", get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }))
        .route("/app.css", get(|| async { asset("text/css; charset=utf-8", APP_CSS) }))
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", api)
}
