use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, QueryResult, QuerySource, RunQueryDsl, Table};
use diesel::query_builder::QueryFragment;
use diesel::query_dsl::filter_dsl::FilterDsl;
use diesel::sqlite::Sqlite;
use crate::crypto::Boolean;
use crate::schema::addresses;
use crate::schema::derivation_paths;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::storage::models::entity::Entity;

/// queries
/// "(derivationPath == %@)"
/// "(derivationPath == %@) && (identityIndex == %@)"
/// "(derivationPath == %@) && (internal == %@)"
/// "derivationPath.chain == %@"
/// "address == %@ && derivationPath.chain == %@"
/// "address IN %@ && derivationPath.chain == %@"
/// indexation
/// "index": ASC

// todo: shall we sandbox it with chain_id?
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = addresses)]
pub struct AddressEntity {
    pub id: i32,
    pub identity_index: i32,
    pub index: i32,
    pub address: String,
    pub internal: Boolean,
    pub standalone: Boolean,


    pub derivation_path_id: Option<i32>,
    // pub used_in_masternode_ids: Vec<i32>,
    // pub used_in_input_ids: Vec<i32>,
    // pub used_in_output_ids: Vec<i32>,
    // pub used_in_special_transaction_ids: Vec<i32>,
}

#[derive(Insertable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = addresses)]
pub struct NewAddressEntity {
    pub identity_index: i32,
    pub index: i32,
    pub address: &'static str,
    pub internal: Boolean,
    pub standalone: Boolean,

    pub derivation_path_id: Option<i32>,
    // pub used_in_masternode_ids: Vec<i32>,
    // pub used_in_input_ids: Vec<i32>,
    // pub used_in_output_ids: Vec<i32>,
    // pub used_in_special_transaction_ids: Vec<i32>,
}

impl Entity for AddressEntity {
    type ID = addresses::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         addresses::dsl::addresses
    }
}

impl AddressEntity {
    pub fn create_with(derivation_path_id: i32, address: &str, index: i32, internal: bool, standalone: bool, context: &ManagedContext) -> QueryResult<usize> {
        Self::create(&NewAddressEntity {
            index,
            address,
            standalone: Boolean(standalone),
            internal: Boolean(internal),
            ..Default::default()
        }, context)
    }

    pub fn get_by_derivation_path_id(derivation_path_id: i32, context: &ManagedContext) -> QueryResult<Vec<AddressEntity>> {
        Self::read(addresses::derivation_path_id.eq(derivation_path_id), context)
    }

    pub fn count_used_in_inputs(&self, context: &ManagedContext) -> QueryResult<usize> {
        todo!()
    }

    pub fn count_used_in_outputs(&self, context: &ManagedContext) -> QueryResult<usize> {
        todo!()
    }



    // get addresses with address and derivation path which chain is equal to id
    // result is Vec<(id, account_id, derivation_path_id)>
    fn _get_id_and_account_id_by_address_and_chain_id<T, P>(address: &String, chain_id: i32, context: &ManagedContext) -> T
        where T: FilterDsl<P> {
        Self::target()
            .inner_join(DerivationPathEntity::target())
            .inner_join(ChainEntity::target())
            .select((Self::ID, derivation_paths::account_id, derivation_paths::chain_id))
            .filter(derivation_paths::chain_id.eq(chain_id).and(addresses::address.eq(address)))
    }

    pub fn get_id_and_account_id_by_address_and_chain_id(address: &String, chain_id: i32, context: &ManagedContext) -> QueryResult<Vec<(i32, i32, i32)>> {
        // @"address == %@ && derivationPath.chain == %@", self.address, chainEntity ? chainEntity : [transaction.chain chainEntityInContext:transactionEntity.managedObjectContext]];
        Self::_get_id_and_account_id_by_address_and_chain_id(address, chain_id, context)
            .get_results::<(i32, i32, i32)>(&context.connection())

    }

    pub fn any_id_and_account_id_by_address_and_chain_id(address: &String, chain_id: i32, context: &ManagedContext) -> QueryResult<(i32, i32, i32)> {
        // @"address == %@ && derivationPath.chain == %@", self.address, chainEntity ? chainEntity : [transaction.chain chainEntityInContext:transactionEntity.managedObjectContext]];
        //assert_eq!(aggregates.len(), 1, "addresses should not be duplicates");
        Self::_get_id_and_account_id_by_address_and_chain_id(address, chain_id, context)
            .first::<(i32, i32, i32)>(&context.connection())
    }


    pub fn count_relationships(&self, context: &ManagedContext) -> QueryResult<usize> {
        // if ([e.usedInInputs count] ||
        //     [e.usedInOutputs count] ||
        //     [e.usedInSpecialTransactions count] ||
        //     [e.usedInSimplifiedMasternodeEntries count]) {
        // TODO:
        Err(diesel::result::Error::NotFound)
    }
}
