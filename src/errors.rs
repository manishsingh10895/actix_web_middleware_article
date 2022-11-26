use actix_web::{ResponseError, HttpResponse, body::{BoxBody, EitherBody}};
use jsonwebtoken::errors::ErrorKind;

#[derive(Debug)]
pub enum AuthError {
    Claims(serde_json::Error),
    /// `Token` is not valid
    InvalidToken,
    /// Request doesn't have a `Authorization` header
    NoAuthorizationHeader,
    /// Authorization Header is not in `Bearer` format
    InvalidAuthorizationHeader,
    /// Token Expired
    TokenExpired,
}

/// Default Error 
impl Default for AuthError {
    fn default() -> AuthError {
        AuthError::InvalidToken
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.into_kind() {
            ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::InvalidToken,
        }
    }
}

// Implementing Display for response strings 
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAuthorizationHeader => {
                write!(f, "Authorization header is not in valid format ")
            }
            Self::NoAuthorizationHeader => write!(f, "No Authorization Header"),
            Self::Claims(e) => write!(f, "Error while Deserializing JWT: {}", e),
            Self::InvalidToken => write!(f, "Invalid JWT Token"),
            Self::TokenExpired => write!(f, "Token Expired"),
        }
    }
}

/// Implement `ResponseError` from actix_web so that we can serialize errors and send it as a response 
impl ResponseError for AuthError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            Self::InvalidAuthorizationHeader => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::FORBIDDEN,
            Self::Claims(_) => StatusCode::FORBIDDEN,
            Self::NoAuthorizationHeader => StatusCode::FORBIDDEN,
            Self::TokenExpired => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::new(self.status_code()).set_body(BoxBody::new(self.to_string()))
    }
}

/// Simple helper function to return `error_response`
impl AuthError {
    pub fn to_response(&self) -> HttpResponse {
        self.error_response()
    }
}