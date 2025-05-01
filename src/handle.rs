use crate::jwt::{generate_jwt, Claims, HashPassword, ValidateHash};
use crate::user::{self, UserCreate};
use crate::user::{ActiveModel, Entity};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use sea_orm::ColumnTrait;
use sea_orm::{ActiveValue::Set, DbConn, EntityTrait, QueryFilter}; // Dodaj ten import, aby móc używać eq

pub async fn register(db: web::Data<DbConn>, user: web::Json<UserCreate>) -> impl Responder {
    // Sprawdzamy, czy użytkownik z takim emailem już istnieje
    let existing_user = Entity::find()
        .filter(user::Column::Email.eq(&user.email)) // Poprawione użycie Column::Email
        .one(&**db)
        .await;

    match existing_user {
        Ok(Some(_)) => {
            return HttpResponse::BadRequest().body("User already exists");
        }
        _ => {}
    }

    // Haszowanie hasła przed zapisaniem
    let hashed_password = HashPassword(&user.password);

    // Tworzymy nowego użytkownika
    let new_user = ActiveModel {
        name: Set(user.name.clone()),
        lastname: Set(user.lastname.clone()),
        age: Set(user.age),
        email: Set(user.email.clone()),
        password: Set(hashed_password),
        ..Default::default()
    };

    // Zapisujemy użytkownika w bazie danych
    let inserted_user = Entity::insert(new_user).exec(&**db).await.unwrap();

    // Uzyskanie ID wstawionego użytkownika
    // Inna opcja, zamiast korzystać z deprecated `last_insert_id`, można dostać ID z inserted_user:
    let user_id = inserted_user.last_insert_id; // Użyj `unwrap_or_default` w razie braku ID

    // Możesz zwrócić użytkownikowi token po zapisaniu
    //let token = generate_jwt(&user_id.to_string());

    HttpResponse::Created().json(serde_json::json!({
        "message": "User created successfully",
    }))
}

pub async fn login(db: web::Data<DbConn>, info: web::Json<UserCreate>) -> impl Responder {
    // Szukamy użytkownika po emailu
    let user = Entity::find()
        .filter(user::Column::Email.eq(&info.email)) // Poprawione użycie Column::Email
        .one(&**db)
        .await
        .unwrap();

    match user {
        Some(user) => {
            // Sprawdzamy, czy hasło się zgadza
            if ValidateHash(&info.password, &user.password) {
                let token = generate_jwt(&user.id.to_string());
                HttpResponse::Ok().json(serde_json::json!({
                    "token": token,
                    "user_id": user.id
                }))
            } else {
                HttpResponse::Unauthorized().body("Invalid credentials")
            }
        }
        None => HttpResponse::NotFound().body("User not found"),
    }
}

pub async fn settings(db: web::Data<DbConn>, req: HttpRequest) -> impl Responder {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // Dekoduj token
            if let Ok(token_data) = jsonwebtoken::decode::<Claims>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(
                    std::env::var("JWT_SECRET").unwrap().as_bytes(),
                ),
                &jsonwebtoken::Validation::default(),
            ) {
                // Parsujemy user_id z pola `sub`
                let user_id = token_data.claims.sub.parse::<i32>().unwrap_or(0);

                // Szukamy użytkownika
                if let Ok(Some(user)) = Entity::find_by_id(user_id).one(&**db).await {
                    return HttpResponse::Ok().json(user);
                }
            }
        }
    }

    HttpResponse::Unauthorized().body("Invalid or missing token")
}

pub async fn update() -> impl Responder {
    HttpResponse::Ok().body("Updated successfully")
}

pub async fn delete() -> impl Responder {
    HttpResponse::Ok().body("Deleted successfully")
}
