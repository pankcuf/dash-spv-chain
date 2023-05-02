use diesel::{ExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::crypto::{Boolean, UInt256, UInt768};
use crate::schema::instant_send_locks;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;
use crate::storage::models::masternode::QuorumEntity;
use crate::storage::models::tx::transaction::TransactionEntity;

/// "transaction.transactionHash.txHash == %@"
///
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = instant_send_locks)]
pub struct InstantSendLockEntity {
    pub id: i32,
    pub verified: Boolean,
    pub signature: UInt768,
    pub quorum_id: Option<i32>,
    pub transaction_id: i32,
    // pub transaction_z27: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = instant_send_locks)]
pub struct NewInstantSendLockEntity {
    pub verified: Boolean,
    pub signature: UInt768,
    pub quorum_id: Option<i32>,
    pub transaction_id: i32,
}

impl Entity for InstantSendLockEntity {
    type ID = instant_send_locks::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        instant_send_locks::dsl::instant_send_locks
    }
}

impl InstantSendLockEntity {
    //+ (DSInstantSendLockEntity *)instantSendLockEntityFromInstantSendLock:(DSInstantSendTransactionLock *)instantSendTransactionLock inContext:(NSManagedObjectContext *)context {
    fn entity_from_model(instant_send_lock: &InstantSendTransactionLock, context: &ManagedContext) -> QueryResult<NewInstantSendLockEntity> {
        match Self::get_transaction_entity(&instant_send_lock.transaction_hash, context) {
            Ok(tx) => {
                // the quorum might not yet
                if let Some(quorum) = &instant_send_lock.intended_quorum {
                    if let Ok(quorum_entity) = QuorumEntity::get_by_public_key(&quorum.public_key, context) {
                        return Ok(NewInstantSendLockEntity {
                            verified: Boolean(instant_send_lock.signature_verified),
                            signature: instant_send_lock.signature,
                            quorum_id: Some(quorum_entity.id),
                            transaction_id: tx.id
                        });
                    }
                }
                Ok(NewInstantSendLockEntity {
                    verified: Boolean(instant_send_lock.signature_verified),
                    signature: instant_send_lock.signature,
                    quorum_id: None,
                    transaction_id: tx.id
                })
            },
            Err(err) => panic!("transaction entity for instant send lock must exist")
        }
    }
}

impl InstantSendLockEntity {

    fn get_transaction_entity(hash: &UInt256, context: &ManagedContext) -> QueryResult<TransactionEntity> {
        TransactionEntity::get_by_tx_hash(hash, context)
    }

    fn get_by_transaction_hash(hash: &UInt256, context: &ManagedContext) -> QueryResult<Self> {
        Self::get_transaction_entity(hash, context)
            .and_then(|tx| Self::get_by_transaction_id(tx.id, context))
    }


    pub fn get_by_transaction_id(transaction_id: i32, context: &ManagedContext) -> QueryResult<InstantSendLockEntity> {
        Self::any(instant_send_locks::transaction_id.eq(transaction_id), context)
    }

    pub fn update_signature_validity_for_lock_with_tx_hash(verified: bool, hash: &UInt256, context: &ManagedContext) -> QueryResult<usize> {
        Self::get_transaction_entity(hash, context)
            .and_then(|tx|
                Self::update(
                    instant_send_locks::transaction_id.eq(tx.id),
                    instant_send_locks::verified.eq(verified),
                    context))
    }

    pub fn create_if_need(instant_send_lock: &InstantSendTransactionLock, context: &ManagedContext) -> QueryResult<usize> {
        match Self::get_transaction_entity(&instant_send_lock.transaction_hash, context) {
            Ok(tx) => {
                match Self::count(instant_send_locks::transaction_id.eq(tx.id), context) {
                    Ok(0) => {
                        // the quorum might not yet
                        if let Some(quorum) = &instant_send_lock.intended_quorum {
                            if let Ok(quorum_entity) = QuorumEntity::get_by_public_key(&quorum.public_key, context) {
                                return Self::create(&NewInstantSendLockEntity {
                                    verified: Boolean(instant_send_lock.signature_verified),
                                    signature: instant_send_lock.signature,
                                    quorum_id: Some(quorum_entity.id),
                                    transaction_id: tx.id
                                }, context);
                            }
                        }
                        Self::create(&NewInstantSendLockEntity {
                            verified: Boolean(instant_send_lock.signature_verified),
                            signature: instant_send_lock.signature,
                            quorum_id: None,
                            transaction_id: tx.id
                        }, context)
                    },
                    Ok(..) => Ok(0),
                    Err(err) => panic!("error retrievint instant send lock entity")
                }
            },
            Err(err) => panic!("transaction entity for instant send lock must exist")
        }
    }
}
