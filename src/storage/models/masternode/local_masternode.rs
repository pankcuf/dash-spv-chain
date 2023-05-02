use diesel::{QueryDsl, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::query_dsl::filter_dsl::FilterDsl;
use diesel::sqlite::Sqlite;
use crate::chain::masternode::local_masternode::LocalMasternode;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::UInt256;
use crate::schema::{local_masternodes, transactions};
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;
use crate::storage::models::masternode::MasternodeEntity;
use crate::storage::models::tx::transaction::TransactionEntity;

/// queries:
/// "providerRegistrationTransaction.transactionHash.txHash == %@"
/// "providerRegistrationTransaction.transactionHash.chain == %@"
/// "(providerRegistrationTransaction.transactionHash.txHash IN %@)"

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
// #[belongs_to(Masternode)]
#[diesel(table_name = local_masternodes)]
pub struct LocalMasternodeEntity {
    pub id: i32,
    pub operator_keys_index: i32,
    pub owner_keys_index: i32,
    pub holding_keys_index: i32,
    pub voting_keys_index: i32,
    pub operator_keys_wallet_unique_id: String,
    pub owner_keys_wallet_unique_id: String,
    pub voting_keys_wallet_unique_id: String,
    pub holding_keys_wallet_unique_id: String,

    pub masternode_id: i32,
    pub provider_registration_transaction_id: Option<i32>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = local_masternodes)]
pub struct NewLocalMasternodeEntity {
    pub operator_keys_index: i32,
    pub owner_keys_index: i32,
    pub holding_keys_index: i32,
    pub voting_keys_index: i32,
    pub operator_keys_wallet_unique_id: &'static str,
    pub owner_keys_wallet_unique_id: &'static str,
    pub voting_keys_wallet_unique_id: &'static str,
    pub holding_keys_wallet_unique_id: &'static str,

    pub masternode_id: i32,
    pub provider_registration_transaction_id: Option<i32>,
}

impl Entity for LocalMasternodeEntity {
    type ID = local_masternodes::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         local_masternodes::dsl::local_masternodes
    }
}

impl LocalMasternodeEntity {
    pub fn count_for_pro_reg_tx_hash(pro_reg_tx_hash: &UInt256, context: &ManagedContext) -> QueryResult<i64> {
        Self::target()
            .inner_join(TransactionEntity::target())
            .filter(transactions::hash.eq(pro_reg_tx_hash))
            .count()
    }

    fn save_from_model(local_masternode: &LocalMasternode, pro_reg_tx_entity: &TransactionEntity, context: &ManagedContext) -> QueryResult<usize> {
        // let mut new_entity: NewLocalMasternodeEntity = local_masternode.to_entity();
        let mut new_entity = NewLocalMasternodeEntity {
            operator_keys_index: local_masternode.operator_wallet_index as i32,
            owner_keys_index: local_masternode.owner_wallet_index as i32,
            holding_keys_index: local_masternode.holding_wallet_index as i32,
            voting_keys_index: local_masternode.voting_wallet_index as i32,
            operator_keys_wallet_unique_id: local_masternode.operator_keys_wallet.map_or("", Wallet::unique_id_as_str),
            owner_keys_wallet_unique_id: local_masternode.owner_keys_wallet.map_or("", Wallet::unique_id_as_str),
            voting_keys_wallet_unique_id: local_masternode.voting_keys_wallet.map_or("", Wallet::unique_id_as_str),
            holding_keys_wallet_unique_id: local_masternode.holding_keys_wallet.map_or("", Wallet::unique_id_as_str),
            ..Default::default()
        };

        new_entity.provider_registration_transaction_id = Some(pro_reg_tx_entity.id);
        // todo: split transaction entities into different tables
        match MasternodeEntity::get_by_pro_reg_tx_hash(&pro_reg_tx_entity.hash, context) {
            Ok(mastenode_entity) => {
                new_entity.masternode_id = mastenode_entity.id;
            },
            Err(diesel::result::Error::NotFound) => println!("Masternode entity with pro_reg_tx_hash {} not found", pro_reg_tx_entity.hash),
            Err(err) => panic!("Error retrieving masternode entity")
        }
        Err(diesel::result::Error::NotFound)
        // todo: impl
        // local_masternode.provider_update_service_transactions.iter().filter_ok(|tx| {
        //     TransactionEntity::get_by_tx_hash(&pro_reg_tx_entity.hash)
        // })


        // DSProviderRegistrationTransactionEntity *providerRegistrationTransactionEntity =
        //     [DSProviderRegistrationTransactionEntity anyObjectInContext:self.managedObjectContext matching:@"transactionHash.txHash == %@", uint256_data(localMasternode.providerRegistrationTransaction.txHash)];
        // self.providerRegistrationTransaction = providerRegistrationTransactionEntity;
        // DSSimplifiedMasternodeEntryEntity *simplifiedMasternodeEntryEntity = [DSSimplifiedMasternodeEntryEntity anyObjectInContext:self.managedObjectContext matching:@"providerRegistrationTransactionHash == %@", uint256_data(localMasternode.providerRegistrationTransaction.txHash)];
        // self.simplifiedMasternodeEntry = simplifiedMasternodeEntryEntity;
        //
        // for (DSProviderUpdateServiceTransaction *providerUpdateServiceTransaction in localMasternode.providerUpdateServiceTransactions) {
        //     DSProviderUpdateServiceTransactionEntity *providerUpdateServiceTransactionEntity = [DSProviderUpdateServiceTransactionEntity anyObjectInContext:self.managedObjectContext matching:@"transactionHash.txHash == %@", uint256_data(providerUpdateServiceTransaction.txHash)];
        //     if (![self.providerUpdateServiceTransactions containsObject:providerUpdateServiceTransactionEntity]) {
        //         [self addProviderUpdateServiceTransactionsObject:providerUpdateServiceTransactionEntity];
        //     }
        // }
        //
        // for (DSProviderUpdateRegistrarTransaction *providerUpdateRegistrarTransaction in localMasternode.providerUpdateRegistrarTransactions) {
        //     DSProviderUpdateRegistrarTransactionEntity *providerUpdateRegistrarTransactionEntity = [DSProviderUpdateRegistrarTransactionEntity anyObjectInContext:self.managedObjectContext matching:@"transactionHash.txHash == %@", uint256_data(providerUpdateRegistrarTransaction.txHash)];
        //     if (![self.providerUpdateRegistrarTransactions containsObject:providerUpdateRegistrarTransactionEntity]) {
        //         [self addProviderUpdateRegistrarTransactionsObject:providerUpdateRegistrarTransactionEntity];
        //     }
        // }
        //
        // for (DSProviderUpdateRevocationTransaction *providerUpdateRevocationTransaction in localMasternode.providerUpdateRevocationTransactions) {
        //     DSProviderUpdateRevocationTransactionEntity *providerUpdateRevocationTransactionEntity = [DSProviderUpdateRevocationTransactionEntity anyObjectInContext:self.managedObjectContext matching:@"transactionHash.txHash == %@", uint256_data(providerUpdateRevocationTransaction.txHash)];
        //     if (![self.providerUpdateRevocationTransactions containsObject:providerUpdateRevocationTransactionEntity]) {
        //         [self addProviderUpdateRevocationTransactionsObject:providerUpdateRevocationTransactionEntity];
        //     }
        // }

    }


    pub fn save(local_masternode: &LocalMasternode, context: &ManagedContext) -> QueryResult<usize> {
        // todo: check optional tx
        let transaction = local_masternode.provider_registration_transaction.unwrap();
        TransactionEntity::save_transaction_if_need_for(transaction.chain().r#type(), transaction, context)
            .and_then(|tx_entity| Self::any(local_masternodes::provider_registration_transaction_id.eq(tx_entity.id), context)
                .and_then(|entity| entity.update_with(local_masternode.to_update_values(), context))
                .or(Self::save_from_model(local_masternode, &tx_entity, context)))


    }

}

// pub fn delete_local_masternodes(chain_id: i32) -> QueryResult<usize> {
//     // need to impl pro_reg_tx and it's join
//     let predicate = schema::local_masternodes::chain_id.eq(chain_id);
//     let source = local_masternodes.filter(predicate);
//     delete(source)
// }


// pub fn local_masternode_for_pro_reg_tx_hash(hash: UInt256) -> QueryResult<LocalMasternode> {
//     let mut pooled_conn = get_pooled_connection();
//     // let predicate  = schema::local_masternodes::provider_registration_transaction
//     local_masternodes::select(local_masternodes, local_masternodes::all_columns())
//         .filter(predicate)
//         .first::<LocalMasternode>(pooled_conn.deref_mut())
// }
