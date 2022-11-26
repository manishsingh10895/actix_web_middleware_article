use futures::{
    future::{ok, ready, LocalBoxFuture, Ready},
    FutureExt,
};

use actix_web::{
    body::EitherBody,
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    http::header::HeaderValue,
    FromRequest, HttpMessage,
};
use chrono::{serde::ts_seconds, DateTime, Utc};
use jsonwebtoken::{decode, decode_header, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{from_value, Value};

use crate::errors::AuthError;

pub struct BasicAuth;
pub struct AuthMiddleware<S> {
    service: S, // S is the type of next service/middleware if any, in the current list of middlewares
}

impl<S, B> Transform<S, ServiceRequest> for BasicAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>; // Type of response from server

    type Error = actix_web::Error;

    type InitError = (); // Error type of any error occures in creating this middleware

    type Transform = AuthMiddleware<S>; // Type to transform into (our middleware)
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddleware { service })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub email: String,
    pub id: String,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct DecodedUser {
    pub email: String,
    pub id: String,
}

impl From<Claims> for DecodedUser {
    fn from(c: Claims) -> Self {
        DecodedUser {
            email: c.email,
            id: c.id,
        }
    }
}

pub struct Authenticated(DecodedUser);

/// Implementing `FromRequest` allows to extract `DecodedUser`
/// from any incoming request where `BasicAuth` middleware is used
impl FromRequest for Authenticated {
    type Error = AuthError;
    // Using `Ready` Future as we don't do any
    // async operation in the `from_request` function
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        // Get cloned value of decoded user from request
        let value = req.extensions().get::<DecodedUser>().cloned();

        let result = match value {
            Some(v) => Ok(Authenticated(v)),
            None => Err(AuthError::InvalidToken),
        };

        futures::future::ready(result)
    }
}

/// Implement deref for `Authenticated` to
/// directly refer to `DecodedUser` when using `.` notation for `Authenticated`
/// Example
/// ```rust
///  let a = Authenticated(DecodedUser{id: "".to_string(), email: String::new()});
///
///  assert_eq!(a.email, String::new()); // refering to `DecodedUser` email directly
/// ```
impl std::ops::Deref for Authenticated {
    type Target = DecodedUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub id: String,
}

impl From<&User> for Claims {
    fn from(user: &User) -> Self {
        use std::ops::Add;
        Claims {
            email: user.email.clone(),
            id: user.id.to_string(),
            exp: Utc::now().add(chrono::Duration::days(1)),
        }
    }
}

const SECRET_KEY: &[u8] = b"SECRETE A SECRET";

/// Encodes required details into a `jwt` token
pub fn encode_token<'a>(user: &'a User) -> Result<String, AuthError> {
    Ok(encode::<Claims>(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &user.into(), // To simplify passing claims, impl From<User> for Claims, there's an example below
        &EncodingKey::from_secret(SECRET_KEY),
    )?)
}

/// Decodes a `jwt` token into `Claims` struct
pub fn decode_token(auth_header: &HeaderValue) -> Result<Claims, AuthError> {
    match auth_header.to_str() {
        Ok(auth_header_string) => {
            let token = auth_header_string.trim_start_matches("Bearer "); // Our Authorization header value should be like `Bearer {token}`

            match decode_header(token) {
                Ok(jwt_header) => {
                    match decode::<Value>(
                        token,
                        &DecodingKey::from_secret(SECRET_KEY),
                        &Validation::new(jwt_header.alg),
                    ) {
                        Ok(raw_token) => {
                            let decoded = from_value::<Claims>(raw_token.claims.clone());

                            match decoded {
                                Ok(claims) => Ok(claims),
                                Err(e) => Err(AuthError::Claims(e)),
                            }
                        }

                        Err(_) => Err(AuthError::InvalidToken),
                    }
                }
                Err(err) => {
                    use jsonwebtoken::errors::ErrorKind;

                    match err.into_kind() {
                        ErrorKind::ExpiredSignature => Err(AuthError::TokenExpired),
                        _ => Err(AuthError::InvalidToken)
                    }
                }
            }
        }
        Err(_) => Err(AuthError::InvalidAuthorizationHeader),
    }
}


/// Implement Service for AuthMiddleware 
impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;

    type Error = actix_web::Error;

    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let mut error: AuthError = AuthError::default();

        match req.headers().get("Authorization") {
            Some(auth_header) => match decode_token(auth_header) {
                Ok(token) => {
                    {
                        // attach user data to request
                        let mut extensions = req.extensions_mut();

                        extensions.insert::<DecodedUser>(token.into());
                    }

                    // Return to next middleware/handler on appending to extensions
                    return Box::pin(
                        self.service
                            .call(req)
                            .map(|res| res.map(|res| res.map_into_left_body())),
                    );
                }
                Err(err) => error = err,
            },
            None => {
                error = AuthError::NoAuthorizationHeader;
            }
        }

        //// Pin is to make sure the future remains in same positions in the memory
        //// So as to make sure the references with the inner future remains intact

        return Box::pin(ready(Ok(
            req.into_response(error.to_response().map_into_right_body())
        )));
    }
}
