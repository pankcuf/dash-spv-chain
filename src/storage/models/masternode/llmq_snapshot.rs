use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::schema::llmq_snapshots;
use crate::storage::models::entity::Entity;
use crate::storage::models::chain::block::BlockEntity;

#[derive(Identifiable, Queryable, Associations, PartialEq, Eq, Debug)]
#[diesel(belongs_to(BlockEntity, foreign_key = block_id))]
#[diesel(table_name = llmq_snapshots)]
pub struct LLMQSnapshotEntity {
    pub id: i32,
    pub member_list: Vec<u8>,
    pub skip_list: Vec<u8>,
    pub skip_list_mode: i32,

    pub block_id: i32,
}

#[derive(Insertable, Associations, PartialEq, Eq, Debug)]
#[diesel(belongs_to(BlockEntity, foreign_key = block_id))]
#[diesel(table_name = llmq_snapshots)]
pub struct NewLLMQSnapshotEntity {
    pub member_list: Vec<u8>,
    pub skip_list: Vec<u8>,
    pub skip_list_mode: i32,

    pub block_id: i32,
}

impl Entity for LLMQSnapshotEntity {
    type ID = llmq_snapshots::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         llmq_snapshots::dsl::llmq_snapshots
    }
}

