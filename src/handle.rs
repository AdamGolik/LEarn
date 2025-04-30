use actix_web::{get, post, web, HttpResponse, Responder};
use sea_orm::{ActiveModelTrait, DbConn, Set};
use serde::Serialize;

use crate::user::{ActiveModel as UserActiveModel, UserCreate};

// Prosty endpoint testowy
#[get("/hello")]
pub async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello, World!")
}

// Struktura odpowiedzi użytkownika bez hasła
#[derive(Serialize)]
struct UserResponse {
    id: i32,
    name: String,
    lastname: String,
    age: i32,
    email: String,
}

#[post("/user")]
async fn create_user(db: web::Data<DbConn>, user_data: web::Json<UserCreate>) -> impl Responder {
    let new_user = user_data.into_inner();

    // Hash the password before inserting
    let hashed_password =
        bcrypt::hash(&new_user.password, bcrypt::DEFAULT_COST).expect("Failed to hash password");

    let user = UserActiveModel {
        name: Set(new_user.name),
        lastname: Set(new_user.lastname),
        age: Set(new_user.age),
        email: Set(new_user.email.clone()),
        password: Set(hashed_password),
        ..Default::default()
    };

    // Dereference `db` to get the `DatabaseConnection`
    match user.insert(&**db).await {
        Ok(user_model) => {
            // Create the UserResponse from the UserActiveModel
            let response = UserResponse {
                id: user_model.id,
                name: user_model.name,
                lastname: user_model.lastname,
                age: user_model.age,
                email: user_model.email,
            };
            HttpResponse::Created().json(response) // Return the created user as JSON
        }
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("Error creating user: {}", err))
        }
    }
}

