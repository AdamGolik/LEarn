use sea_orm::entity::prelude::*;
use sea_orm::sea_query::Expr;
use serde::{Deserialize, Serialize};

// Define the User struct (used for User creation request)
#[derive(Serialize, Deserialize, Debug)]
pub struct UserCreate {
    pub name: String,
    pub lastname: String,
    pub age: i32,
    pub email: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    pub lastname: String,
    pub age: i32,
    pub email: String,
    pub password: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

