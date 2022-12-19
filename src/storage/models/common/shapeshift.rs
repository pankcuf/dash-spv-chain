use chrono::NaiveDateTime;
use diesel::{QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::schema::shapeshifts;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;

pub enum ShapeshiftAddressStatus {
    Unused = 0,
    NoDeposits = 1,
    Received = 2,
    Complete = 4,
    Failed = 8,
    Finished = ShapeshiftAddressStatus::Complete | ShapeshiftAddressStatus::Failed,
}

impl From<ShapeshiftAddressStatus> for i16 {
    fn from(value: ShapeshiftAddressStatus) -> Self {
        match value {
            ShapeshiftAddressStatus::Unused => 0,
            ShapeshiftAddressStatus::NoDeposits => 1,
            ShapeshiftAddressStatus::Received => 2,
            ShapeshiftAddressStatus::Complete => 4,
            ShapeshiftAddressStatus::Failed => 8,
            ShapeshiftAddressStatus::Finished => ShapeshiftAddressStatus::Complete | ShapeshiftAddressStatus::Failed,
        }
    }
}
impl From<i16> for ShapeshiftAddressStatus {
    fn from(value: i16) -> Self {
        let finished = ShapeshiftAddressStatus::Complete | ShapeshiftAddressStatus::Failed;
        match value {
            0 => ShapeshiftAddressStatus::Unused,
            1 => ShapeshiftAddressStatus::NoDeposits,
            2 => ShapeshiftAddressStatus::Received,
            4 => ShapeshiftAddressStatus::Complete,
            8 => ShapeshiftAddressStatus::Failed,
            finished => ShapeshiftAddressStatus::Finished,
            _ => ShapeshiftAddressStatus::Unused
        }
    }
}


/// queries:
/// "(shapeshiftStatus == %@) || ((shapeshiftStatus == %@) && (SUBQUERY(transaction.outputs, $output, ($output.shapeshiftOutboundAddress != NIL)).@count == 1))"
/// indexation:
/// "expiresAt": DESC
#[derive(Identifiable, Queryable, PartialEq, Debug)]
pub struct ShapeshiftEntity {
    pub id: i32,

    pub input_coin_amount: f64,
    pub output_coin_amount: f64,
    pub expires_at: NaiveDateTime,
    pub shapeshift_status: i16,
    pub is_fixed_amount: bool,
    pub error_message: String,
    pub input_address: String,
    pub input_coin_type: String,
    pub output_coin_type: String,
    pub output_transaction_id: String,
    pub withdrawal_address: String,

    pub transaction_id: i32,
}

#[derive(Insertable, PartialEq, Debug)]
#[table_name="shapeshifts"]
pub struct NewShapeshiftEntity {
    pub input_coin_amount: f64,
    pub output_coin_amount: f64,
    pub expires_at: NaiveDateTime,
    pub shapeshift_status: i16,
    pub is_fixed_amount: bool,
    pub error_message: &'static str,
    pub input_address: &'static str,
    pub input_coin_type: &'static str,
    pub output_coin_type: &'static str,
    pub output_transaction_id: &'static str,
    pub withdrawal_address: &'static str,

    pub transaction_id: i32,
}

impl Entity for ShapeshiftEntity {
    type ID = shapeshifts::id;
    type ChainId = None;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        shapeshifts::dsl::shapeshifts
    }
}


impl ShapeshiftEntity {
    pub fn having_withdrawal_address(address: &String, context: &ManagedContext) -> QueryResult<Self> {
        //[DSShapeshiftEntity shapeshiftHavingWithdrawalAddress:outboundShapeshiftAddress inContext:[NSManagedObjectContext chainContext]]
        todo!()
    }

    pub fn register_shapeshift_with_addess(address: &String, withdrawal_address: &String, status: ShapeshiftAddressStatus, context: &ManagedContext) -> QueryResult<Self> {
        //[DSShapeshiftEntity registerShapeshiftWithInputAddress:mainOutputAddress andWithdrawalAddress:outboundShapeshiftAddress withStatus:eShapeshiftAddressStatus_NoDeposits inContext:[NSManagedObjectContext chainContext]];
        todo!()
    }
}
