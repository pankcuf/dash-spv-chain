use byte::TryRead;
// use diesel::{Insertable, QuerySource, Table};
// use diesel::insertable::CanInsertInSingleQuery;
// use diesel::query_builder::QueryFragment;
// use diesel::sqlite::Sqlite;
use crate::chain::chain::Chain;
use crate::chain::ext::derivation::Derivation;
use crate::chain::ext::settings::Settings;
use crate::chain::ext::wallets::Wallets;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::chain::tx::Transaction;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::transaction_input::TransactionInput;
use crate::chain::tx::transaction_output::TransactionOutput;
use crate::chain::tx::transaction_type::TransactionType;
use crate::chain::wallet::extension::identities::WalletIdentities;
use crate::chain::wallet::extension::invitations::WalletInvitations;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::{UInt160, UInt256};
use crate::crypto::byte_util::{AsBytes, clone_into_array, Reversable, Zeroable};
use crate::crypto::UTXO;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::simple_indexed_derivation_path::ISimpleIndexedDerivationPath;
use crate::platform::identity::identity::Identity;
use crate::platform::identity::invitation::Invitation;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
// use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
// use crate::storage::models::tx::special::credit_funding_transaction::CreditFundingTransactionEntity;
use crate::storage::models::tx::transaction::NewTransactionEntity;
use crate::util::address::Address;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreditFundingTransaction {
    pub base: Transaction,
}

impl CreditFundingTransaction {

    pub fn locked_outpoint(&self) -> UTXO {
        self.outputs().iter().enumerate().find_map(|(i, TransactionOutput {script, ..})| {
            script.and_then(|s| match &s[..] {
                [b'\x6a', ..] if s.len() == 22 => Some(UTXO { hash: self.tx_hash().clone().reversed(), n: i as u32}),
                _ => None
            })
        }).unwrap_or(UTXO::default())
    }

    pub fn credit_burn_identity_identifier(&self) -> UInt256 {
        let outpoint = self.locked_outpoint();
        if outpoint.is_zero() {
            UInt256::MIN
        } else {
            UInt256::sha256d(outpoint.as_bytes())
        }
    }

    pub fn credit_burn_public_key_hash(&self) -> UInt160 {
        self.outputs().iter()
            .find_map(|output|
                output.script
                    .and_then(|script|
                        match &script[..] {
                            [0x6a, _, other @ ..] if script.len() == 22 => Some(UInt160(clone_into_array(other))),
                            _ => None
                        }))
            .unwrap_or(UInt160::MIN)
    }

    fn credit_burn_address(&self) -> Option<String> {
        Some(Address::from_hash160_for_script_map(&self.credit_burn_public_key_hash(), self.chain().script()))
    }

    // pub fn used_derivation_path_index_for_wallet(&self, wallet: &Wallet) -> u32 {
    //     self.credit_burn_address()
    //         .and_then(|address| self.chain()
    //             .identity_registration_funding_derivation_path_for_wallet(wallet)
    //             .index_of_known_address(&address))
    //         .unwrap_or(u32::MAX)
    // }
    //
    // pub fn check_derivation_path_index_for_wallet_is(&self, wallet: &Wallet, index: u32) -> bool {
    //     // // todo: check None == None comparison
    //     self.credit_burn_address()
    //         .map(|address| self.chain()
    //             .identity_registration_funding_derivation_path_for_wallet(wallet)
    //             .address_at_index(index) == Some(address))
    //         .unwrap_or(false)
    // }
    //
    // pub fn check_invitation_derivation_path_index_for_wallet_is(&self, wallet: &Wallet, index: u32) -> bool {
    //     // todo: check None == None comparison
    //     self.credit_burn_address()
    //         .map(|address| self.chain()
    //             .identity_invitation_funding_derivation_path_for_wallet(wallet)
    //             .address_at_index(index) == Some(address))
    //         .unwrap_or(false)
    // }

    pub fn mark_address_as_used_in_wallet(&self, wallet: &Wallet) {
        if let Some(address) = self.credit_burn_address() {
            let mut path = self.chain().identity_registration_funding_derivation_path_for_wallet(wallet);
            path.register_transaction_address(&address);
            path.register_addresses_with_gap_limit(10).expect("TODO: panic message");
        }
    }

    pub fn mark_invitation_address_as_used_in_wallet(&mut self, wallet: &Wallet) {
        if let Some(address) = self.credit_burn_address() {
            let mut path = self.chain().identity_invitation_funding_derivation_path_for_wallet(wallet);
            path.register_transaction_address(&address);
            path.register_addresses_with_gap_limit(10).expect("TODO: panic message");
        }
    }

    // pub fn used_derivation_path_index(&self) -> u32 {
    //     let accounts = self.accounts();
    //     // let mut wallets = Vec::<Wallet>::new();
    //     match accounts.len() {
    //         0 => u32::MAX,
    //         1 => self.used_derivation_path_index_for_wallet(&self.first_account().unwrap().wallet.unwrap()),
    //         _ => {
    //             accounts.iter().fold(Vec::<&Wallet>::new(), |mut wallets, account| {
    //                 if let Some(wallet) = account.wallet {
    //                     if !wallets.contains(&wallet) {
    //                         wallets.push(wallet);
    //                     }
    //                 }
    //                 wallets
    //             }).iter().map(|wallet| self.used_derivation_path_index_for_wallet(wallet))
    //                 .find(|der| *der != u32::MAX)
    //                 .unwrap_or(u32::MAX)
    //         }
    //     }
    // }
}

// impl EntityConvertible for CreditFundingTransaction {
//     fn to_entity<T, U>(&self) -> U
//         where
//             T: Table + QuerySource,
//             T::FromClause: QueryFragment<Sqlite>,
//             U: Insertable<T>,
//             U::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {
//         todo!()
//     }
//
//     fn to_update_values(&self) -> Box<dyn EntityUpdates<bool, ResultType = (bool, )>> {
//         todo!()
//     }
//
//     fn from_entity<T: Entity>(entity: (CreditFundingTransactionEntity, TransactionEntity), context: &ManagedContext) -> Self {
//         todo!()
//         // let base = match ChainEntity::get_by_id(entity.chain_id, context) {
//         //     Ok(chain) =>
//         // }
//         // DSCreditFundingTransaction *transaction = (DSCreditFundingTransaction *)[super transactionForChain:chain];
//         // transaction.type = DSTransactionType_Classic;
//         // [self.managedObjectContext performBlockAndWait:^{
//         //     transaction.instantSendLockAwaitingProcessing = [self.instantSendLock instantSendTransactionLockForChain:chain];
//         // }];
//         //
//         // return transaction;
//
//     }
// }

impl ITransaction for CreditFundingTransaction {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }

    fn r#type(&self) -> TransactionType {
        TransactionType::CreditFunding
    }

    fn block_height(&self) -> u32 {
        self.base.block_height()
    }

    fn tx_hash(&self) -> UInt256 {
        self.base.tx_hash()
    }

    fn tx_lock_time(&self) -> u32 {
        self.base.tx_lock_time()
    }

    fn inputs(&self) -> Vec<TransactionInput> {
        self.base.inputs()
    }

    fn outputs(&self) -> Vec<TransactionOutput> {
        self.base.outputs()
    }

    fn input_addresses(&self) -> Vec<String> {
        self.base.input_addresses()
    }

    fn output_addresses(&self) -> Vec<String> {
        self.base.output_addresses()
    }

    fn size(&self) -> usize {
        self.base.size()
    }

    fn payload_data(&self) -> Vec<u8> {
        self.base.payload_data()
    }

    fn to_data_with_subscript_index(&self, subscript_index: Option<u64>) -> Vec<u8> {
        self.base.to_data_with_subscript_index(subscript_index)
    }

    fn set_instant_send_received_with_instant_send_lock(&mut self, instant_send_lock: Option<&InstantSendTransactionLock>) {
        let mut is_signature_verified = false;
        if let Some(lock) = instant_send_lock {
            is_signature_verified = lock.signature_verified;
            self.base.instant_send_received = is_signature_verified;
            self.base.has_unverified_instant_send_lock = !is_signature_verified;
            // we will always need to send this platform
            self.base.instant_send_lock_awaiting_processing = instant_send_lock;
            if !lock.saved {
                lock.save_initial();
            }
        } else {
            self.base.instant_send_received = false;
            self.base.has_unverified_instant_send_lock = false;
            self.base.instant_send_lock_awaiting_processing = None;
        }
    }

    fn is_coinbase_classic_transaction(&self) -> bool {
        self.base.is_coinbase_classic_transaction()
    }

    fn has_non_dust_output_in_wallet(&self, wallet: &Wallet) -> bool {
        self.base.has_non_dust_output_in_wallet(wallet)
    }

    fn set_initial_persistent_attributes_in_context(&mut self, context: &ManagedContext) -> bool {
        todo!()
    }

    fn to_entity_with_chain_entity(&self, chain_entity: ChainEntity) -> NewTransactionEntity {
        let mut base = self.base.to_entity_with_chain_entity(chain_entity);
        base
    }

    fn trigger_updates_for_local_references(&self) {

        if let Some((wallet, index)) = self.chain().wallet_having_identity_credit_funding_registration_hash(&self.credit_burn_public_key_hash()) {
            let identity = wallet.identity_for_unique_id(self.credit_burn_identity_identifier());
            if identity.is_none() {
                let mut identity = Identity::init_at_with_credit_funding_transaction_and_username_dictionary(index, self, None, wallet);
                identity.register_in_wallet_for_registration_funding_transaction(self);
            }
        } else if let Some((wallet, index)) = self.chain().wallet_having_identity_credit_funding_invitation_hash(&self.credit_burn_public_key_hash()) {
            let invitation = wallet.invitation_for_unique_id(self.credit_burn_identity_identifier());
            if invitation.is_none() {
                let mut invitation = Invitation::init_at_with_funding_transaction(index, self, wallet);
                invitation.register_in_wallet_for_registration_funding_transaction(self);
            }
        }
    }

    fn associate_with_accepted_invitation(&self, invitation: &Invitation, index: u32, dashpay_username: String, wallet: &Wallet) -> Identity {
        let mut identity = Identity::init_at_with_credit_funding_transaction_and_username_dictionary(index, self, None, wallet);
        identity.set_associated_invitation(invitation);
        identity.add_dashpay_username(dashpay_username, false);
        identity.register_in_wallet_for_registration_funding_transaction(self);
        identity
    }

    fn load_blockchain_identities_from_derivation_paths(&mut self, derivation_paths: Vec<&dyn IDerivationPath>) {
        self.base.load_blockchain_identities_from_derivation_paths(derivation_paths)
    }
}

impl<'a> TryRead<'a, &Chain> for CreditFundingTransaction {
    fn try_read(bytes: &'a [u8], chain: &Chain) -> byte::Result<(Self, usize)> {
        let (mut base, mut offset) = Transaction::try_read(bytes, chain)?;
        base.tx_type = TransactionType::CreditFunding;
        Ok((Self { base }, offset))
    }
}
