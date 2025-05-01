use std::env;

use actix_service::{Service, Transform};
use actix_web::dev::ServiceRequest;
use actix_web::{dev::ServiceResponse, Error, HttpResponse};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use futures_util::future::Ready;
use futures_util::future::{ok, LocalBoxFuture};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{
    rc::Rc,
    task::{Context, Poll},
};

pub fn hash_password(password: &str) -> String {
    let hash = hash(password, DEFAULT_COST).unwrap();
    hash
}
pub fn vaildate_hash(password: &str, hash: &str) -> bool {
    let validate = verify(password, hash).unwrap_or(false);
    validate
}
// JWT klucz (do testów — w produkcji bezpiecznie trzymaj!)
fn get_jwt_secret() -> Vec<u8> {
    env::var("JWT_SECRET")
        .expect("JWT_SECRET not set")
        .into_bytes()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

// Wygeneruj token
pub fn generate_jwt(username: &str) -> String {
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&get_jwt_secret()),
    )
    .unwrap()
}

// === JWT Middleware ===

#[derive(Clone)]
pub struct JwtMiddleware;

impl<S> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = JwtMiddlewareMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareMiddleware {
            service: Rc::new(service),
        })
    }
}

type BoxBody = actix_web::body::BoxBody;

pub struct JwtMiddlewareMiddleware<S> {
    service: Rc<S>,
}

impl<S> Service<ServiceRequest> for JwtMiddlewareMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok());

        if let Some(auth_header) = auth_header {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                let validation = Validation::default();
                let result = decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(&get_jwt_secret()),
                    &validation,
                );

                if result.is_ok() {
                    let fut = self.service.call(req);
                    return Box::pin(async move { fut.await });
                }
            }
        }

        let (req, _payload) = req.into_parts();
        let response = HttpResponse::Unauthorized()
            .body("Invalid or missing token")
            .map_into_boxed_body();
        let res = ServiceResponse::new(req, response);
        Box::pin(async { Ok(res) })
    }
}
