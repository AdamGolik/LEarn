use async_trait::async_trait;
use sea_orm::entity::prelude::*;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{integer, pk_auto, string};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
