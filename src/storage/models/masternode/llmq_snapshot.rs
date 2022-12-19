use diesel::{QueryResult, QuerySource, Table};
use diesel::associations::HasTable;
use diesel::query_builder::{IntoUpdateTarget, QueryFragment, QueryId};
use diesel::sqlite::Sqlite;
use crate::schema::llmq_snapshots;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, Associations, PartialEq, Eq, Debug)]
pub struct LLMQSnapshotEntity {
    pub id: i32,
    pub member_list: Vec<u8>,
    pub skip_list: Vec<u8>,
    pub skip_list_mode: i32,

    pub block_id: i32,
}

#[derive(Insertable, Associations, PartialEq, Eq, Debug)]
#[table_name="llmq_snapshots"]
pub struct NewLLMQSnapshotEntity {
    pub member_list: Vec<u8>,
    pub skip_list: Vec<u8>,
    pub skip_list_mode: i32,

    pub block_id: i32,
}

impl Entity for LLMQSnapshotEntity {
    type ID = llmq_snapshots::id;
    type ChainId = None;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T
        where
            T: Table + QuerySource,
            T::FromClause: QueryFragment<Sqlite> {
        llmq_snapshots::dsl::llmq_snapshots
    }
}

