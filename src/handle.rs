use std::collections::HashMap;

use crate::jwt::Claims;
use crate::jwt::HashPassword;
use crate::jwt::{generate_jwt, ValidateHash};
use crate::post::ActiveModel as ActiveModel_todo;
use crate::post::Column as PostColumn;
use crate::post::Entity as Entity_post;
use crate::post::PostCreate;
use crate::user::{self, UserCreate};
use crate::user::{ActiveModel, Entity};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{decode, DecodingKey, Validation};
use sea_orm::ColumnTrait;
use sea_orm::DbConn;
use sea_orm::DbErr;
use sea_orm::QueryFilter;
use sea_orm::{ActiveModelTrait, EntityTrait, Set}; // Dodaj ten import, aby móc używać eq
use serde::Serialize;

#[derive(Serialize)]
pub struct UserWithPosts {
    pub id: i32,
    pub name: String,
    pub lastname: String,
    pub age: i32,
    pub email: String,
    pub posts: Option<Vec<PostCreate>>,
}
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
    let _user_id = inserted_user.last_insert_id; // Użyj `unwrap_or_default` w razie braku ID

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

pub async fn update(
    db: web::Data<DbConn>,
    req: HttpRequest,
    user: web::Json<UserCreate>,
) -> impl Responder {
    // Pobierz Authorization header
    let auth_header = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
    {
        Some(h) => h,
        None => return HttpResponse::Unauthorized().body("Missing Authorization header"),
    };

    // Wyciągnij token
    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Invalid token format"),
    };

    // Dekoduj token
    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(std::env::var("JWT_SECRET").unwrap().as_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };

    // Parsuj user_id z tokena
    let user_id = token_data.claims.sub.parse::<i32>().unwrap_or(0);

    // Znajdź użytkownika
    let existing = match Entity::find_by_id(user_id).one(&**db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
        Err(_) => return HttpResponse::InternalServerError().body("Database error"),
    };

    // Zrób hash nowego hasła
    let hashed_password = HashPassword(&user.password);

    // Aktualizuj dane
    let mut updated_user: ActiveModel = existing.into();
    updated_user.name = Set(user.name.clone());
    updated_user.lastname = Set(user.lastname.clone());
    updated_user.age = Set(user.age);
    updated_user.email = Set(user.email.clone());
    updated_user.password = Set(hashed_password);

    // Zapisz zmiany
    if let Err(_) = updated_user.update(&**db).await {
        return HttpResponse::InternalServerError().body("Failed to update user");
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "User updated successfully"
    }))
}

pub async fn delete(db: web::Data<DbConn>, req: HttpRequest) -> impl Responder {
    // Pobierz Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // Dekoduj token
            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_secret(std::env::var("JWT_SECRET").unwrap().as_bytes()),
                &Validation::default(),
            );

            if let Ok(token_data) = token_data {
                let user_id = token_data.claims.sub.parse::<i32>().unwrap_or(0);

                // Sprawdź, czy użytkownik istnieje
                match Entity::find_by_id(user_id).one(&**db).await {
                    Ok(Some(user)) => {
                        // Usuń użytkownika
                        let _ = Entity::delete_by_id(user_id).exec(&**db).await;
                        return HttpResponse::Ok().json(serde_json::json!({
                            "message": "User deleted successfully",
                            "deleted_user": user
                        }));
                    }
                    Ok(None) => return HttpResponse::NotFound().body("User not found"),
                    Err(_) => return HttpResponse::InternalServerError().body("Database error"),
                }
            }
        }
    }

    HttpResponse::Unauthorized().body("Invalid or missing token")
}

pub async fn add_post(
    db: web::Data<DbConn>,
    req: HttpRequest,
    post: web::Json<PostCreate>,
) -> impl Responder {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // Dekoduj token JWT
            let jwt_secret = std::env::var("JWT_SECRET").unwrap();
            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_secret(jwt_secret.as_bytes()),
                &Validation::default(),
            );

            if let Ok(token_data) = token_data {
                let user_id = token_data.claims.sub.parse::<i32>().unwrap_or(0);

                // Sprawdź, czy użytkownik istnieje
                match Entity::find_by_id(user_id).one(&**db).await {
                    Ok(Some(_user)) => {
                        // Sprawdź czy post o takim tytule już istnieje
                        let existing_post = Entity_post::find()
                            .filter(PostColumn::Title.eq(&post.title))
                            .one(&**db)
                            .await;

                        if let Ok(Some(_)) = existing_post {
                            return HttpResponse::BadRequest().body("Post already exists");
                        }

                        // Tworzymy i zapisujemy nowy post
                        let new_post = ActiveModel_todo {
                            title: Set(post.title.clone()),
                            content: Set(post.content.clone()),
                            user_id: Set(user_id),
                            ..Default::default()
                        };

                        match new_post.insert(&**db).await {
                            Ok(saved_post) => HttpResponse::Created().json(saved_post),
                            Err(e) => {
                                println!("Post insert error: {:?}", e);
                                HttpResponse::InternalServerError().body("Failed to save post")
                            }
                        }
                    }
                    Ok(None) => HttpResponse::NotFound().body("User not found"),
                    Err(_) => HttpResponse::InternalServerError().body("Database error"),
                }
            } else {
                HttpResponse::Unauthorized().body("Invalid token")
            }
        } else {
            HttpResponse::Unauthorized().body("Missing Bearer token")
        }
    } else {
        HttpResponse::Unauthorized().body("Authorization header missing")
    }
}

pub async fn get_users_with_posts(db: web::Data<DbConn>) -> Result<Vec<UserWithPosts>, DbErr> {
    let users = Entity::find()
        .find_with_related(Entity_post)
        .all(&**db)
        .await?;

    let result = users
        .into_iter()
        .map(|(u, posts)| UserWithPosts {
            id: u.id,
            name: u.name,
            lastname: u.lastname,
            age: u.age,
            email: u.email,

            // Correct the Post mapping issue
            posts: Some(
                posts
                    .into_iter()
                    .map(|p| PostCreate {
                        title: p.title,
                        content: p.content, // Fix the content mapping
                    })
                    .collect(),
            ),
        })
        .collect();

    Ok(result)
}
// funkcja na określony limit czasu
pub async fn get_users(db: web::Data<DbConn>) -> impl Responder {
    // Corrected line where we pass db as web::Data<DbConn> directly
    match get_users_with_posts(db).await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

pub async fn settings(db: web::Data<DbConn>, req: HttpRequest) -> impl Responder {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // Decode token
            if let Ok(token_data) = jsonwebtoken::decode::<Claims>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(
                    std::env::var("JWT_SECRET").unwrap().as_bytes(),
                ),
                &jsonwebtoken::Validation::default(),
            ) {
                // Parse user_id from `sub`
                let user_id = match token_data.claims.sub.parse::<i32>() {
                    Ok(id) => id,
                    Err(_) => return HttpResponse::Unauthorized().body("Invalid user ID in token"),
                };

                // Look for user
                if let Ok(Some(_user)) = Entity::find_by_id(user_id).one(&**db).await {
                    let user_with_post = Entity::find_by_id(user_id)
                        .find_also_related(Entity_post)
                        .all(&**db)
                        .await;

                    return match user_with_post {
                        Ok(data) => {
                            let mut user_map: HashMap<i32, UserWithPosts> = HashMap::new();

                            for (user, maybe_post) in data {
                                let entry =
                                    user_map.entry(user.id).or_insert_with(|| UserWithPosts {
                                        id: user.id,
                                        name: user.name.clone(),
                                        lastname: user.lastname.clone(),
                                        age: user.age,
                                        email: user.email.clone(),
                                        posts: Some(vec![]),
                                    });

                                if let Some(post) = maybe_post {
                                    // Przekształcenie post::Model -> PostCreate, jeśli potrzebne
                                    let converted_post = PostCreate {
                                        title: post.title.clone(),
                                        content: post.content.clone(),
                                        // inne pola, jeśli są
                                    };

                                    if let Some(ref mut posts) = entry.posts {
                                        posts.push(converted_post);
                                    }
                                }
                            }

                            let result: Vec<UserWithPosts> = user_map.into_values().collect();
                            HttpResponse::Ok().json(result)
                        }
                        Err(_) => HttpResponse::InternalServerError().body("Database error"),
                    };
                }
            }
        }
    }

    HttpResponse::Unauthorized().body("Invalid or missing token")
}
