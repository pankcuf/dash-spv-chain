use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::checkpoints;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = checkpoints)]
pub struct CheckpointEntity {
    pub id: i32,
    pub height: i32,
    pub hash: UInt256,
    pub timestamp: NaiveDateTime,
    pub target: i32,
    pub masternode_list_path: Option<String>,
    pub merkle_root: Option<UInt256>,
    pub chain_work: UInt256,

    pub chain_id: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = checkpoints)]
pub struct NewCheckpointEntity {
    pub height: i32,
    pub hash: UInt256,
    pub timestamp: NaiveDateTime,
    pub target: i32,
    pub masternode_list_path: Option<&'static str>,
    pub merkle_root: Option<UInt256>,
    pub chain_work: UInt256,

    pub chain_id: i32,
}

impl Entity for CheckpointEntity {
    type ID = checkpoints::id;
    // type ChainId = checkpoints::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        checkpoints::dsl::checkpoints
    }
}

impl CheckpointEntity {

    pub fn checkpoints_by_chain_id(chain_id: i32, context: &ManagedContext) -> QueryResult<Vec<Self>> {
        Self::read(checkpoints::chain_id.eq(chain_id), context)
    }
}
