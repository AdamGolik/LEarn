use async_trait::async_trait;
use sea_orm_migration::prelude::*; // Import prelude which includes necessary items like `foreign_key`
use sea_orm_migration::schema::{integer, pk_auto, string};
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(pk_auto(Users::Id)) // Primary key column
                    .col(string(Users::Name)) // Name column, not null
                    .col(string(Users::Lastname)) // Lastname column, nullable
                    .col(integer(Users::Age)) // Age column, not null
                    .col(string(Users::Email).unique_key()) // Email column, unique and not null
                    .col(string(Users::Password)) // Password column, not null
                    .to_owned(),
            )
            .await?;

        // Create posts table with foreign key to users
        manager
            .create_table(
                Table::create()
                    .table(Posts::Table)
                    .if_not_exists()
                    .col(pk_auto(Posts::Id)) // Primary key column
                    .col(string(Posts::Title)) // Title column, not null
                    .col(string(Posts::Content)) // Content column, nullable
                    .col(integer(Posts::UserId)) // Foreign key to User
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk_posts_user")
                            .from(Posts::Table, Posts::UserId) // Foreign key column in Posts
                            .to(Users::Table, Users::Id) // Referencing Users table column
                            .on_delete(ForeignKeyAction::Cascade), // Action on delete
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Posts::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Name,
    Lastname,
    Age,
    Email,
    Password,
}

#[derive(DeriveIden)]
enum Posts {
    Table,
    Id,
    Title,
    Content,
    UserId,
}
