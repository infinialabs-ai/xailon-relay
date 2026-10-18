use sea_orm::entity::prelude::*;

/// A channel claimed by the first authenticated connection. Only connections
/// that present the same token may use it until the claim expires.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "channels")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub relay_id: String,
    /// Hex SHA-256 verifier of the auth token; see `relay::auth::verifier`.
    pub verifier: String,
    #[sea_orm(indexed)]
    pub last_seen_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
