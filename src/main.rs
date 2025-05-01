use actix_web::{middleware::Logger, web, App, HttpServer};

use dotenv::dotenv;

use jwt::JwtMiddleware;
use migration::{Migrator, MigratorTrait};
use sea_orm::{Database, DatabaseConnection};
use std::env;

mod handle;
mod jwt;
mod post;
mod user; // Ensure this module is included
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Fetch the database URL from the environment variables
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Connect to the database
    let db: DatabaseConnection = Database::connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    // Run the 'up' migration to create the tables again
    match Migrator::up(&db, None).await {
        Ok(_) => println!("Database migrations ran successfully."),
        Err(e) => {
            eprintln!("Failed to apply 'up' migration: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Migration up failed",
            ));
        }
    }
    // Start the Actix Web server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone())) // Share database connection with the app
            .service(web::resource("/all").route(web::get().to(handle::get_users)))
            .service(web::resource("/login").route(web::post().to(handle::login)))
            .service(web::resource("/register").route(web::post().to(handle::register)))
            .wrap(Logger::new("%a %r %s %b %D %U %{User-Agent}i"))
            .service(
                web::scope("/user")
                    .wrap(JwtMiddleware)
                    .route("/settings", web::get().to(handle::settings))
                    .route("/update", web::put().to(handle::update))
                    .route("/delete", web::delete().to(handle::delete)),
            )
            .service(
                web::scope("/todos")
                    .wrap(JwtMiddleware)
                    .route("/add", web::post().to(handle::add_post)),
            )
    })
    .bind(("127.0.0.1", 8000))? // Bind to localhost on port 8080
    .run()
    .await
}
