use actix_web::{web, App, HttpResponse, HttpServer, route};
use middleware::{encode_token, Authenticated, BasicAuth, User};
use serde::{Deserialize};

mod errors;
mod middleware;

#[derive(Debug, Deserialize)]
pub struct AuthData {
    pub email: String,
    pub password: String,
}

/// Login a user
pub async fn login(auth_data: web::Json<AuthData>) -> Result<HttpResponse, actix_web::Error> {
    // Validate user, password
    
    let user = User {
        email: auth_data.email.clone(),
        id: "random_string".to_string(),
    };
    
    let token = encode_token(&user)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "token": token })))
}

// Another way to declare routes in actix_web
#[route("/me", method = "GET", wrap = "BasicAuth")]
pub async fn me(auth: Authenticated) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "email": auth.email }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || {
        App::new().service(
            web::scope("/api")
                .service(web::resource("/auth/login").route(web::post().to(login)))
                .service(
                    web::scope("user")
                    .wrap(BasicAuth)
                    .service(me)
                )
        )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
