use std::cmp;
use std::cmp::{min, Ordering};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use secp256k1::rand::{Rng, thread_rng};
use crate::blockdata::opcodes::all::{OP_RETURN, OP_SHAPESHIFT};
use crate::chain::chain::Chain;
use crate::chain::dispatch_context::DispatchContext;
use crate::chain::network::peer::{DAY_TIME_INTERVAL, HOUR_TIME_INTERVAL};
use crate::chain::tx::{CoinbaseTransaction, Transaction, TransactionType};
use crate::chain::tx::transaction::ITransaction;
use crate::chain::params::{BITCOIN_PUBKEY_ADDRESS, TX_INPUT_SIZE, TX_MAX_SIZE, TX_MIN_OUTPUT_AMOUNT, TX_OUTPUT_SIZE, TX_UNCONFIRMED};
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::tx::provider_registration_transaction::{MASTERNODE_COST, ProviderRegistrationTransaction};
use crate::chain::tx::provider_update_registrar_transaction::ProviderUpdateRegistrarTransaction;
use crate::chain::tx::provider_update_service_transaction::ProviderUpdateServiceTransaction;
use crate::chain::tx::transaction_direction::TransactionDirection;
use crate::chain::tx::transaction_sort_type::TransactionSortType;
use crate::chain::wallet::bip39_mnemonic::{BIP39_CREATION_TIME, BIP39_WALLET_UNKNOWN_CREATION_TIME};
use crate::chain::wallet::extension::seed::SeedCompletionBlock;
use crate::chain::wallet::wallet::Wallet;
use crate::consensus::{Encodable, WriteExt};
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::{Reversable, Zeroable};
use crate::crypto::data_ops::{DataAppend, inplace_intersection};
use crate::crypto::UInt256;
use crate::crypto::primitives::utxo::UTXO;
use crate::derivation::derivation_path;
use crate::derivation::derivation_path::{DerivationPath, DerivationPathKind, IDerivationPath, SequenceGapLimit};
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::funds_derivation_path::FundsDerivationPath;
use crate::derivation::incoming_funds_derivation_path::IncomingFundsDerivationPath;
use crate::derivation::uint256_index_path::IIndexPath;
use crate::keys::key::IKey;
use crate::manager::governance_sync_manager::PROPOSAL_COST;
use crate::notifications::{Notification, NotificationCenter};
use crate::platform::identity::potential_one_way_friendship::PotentialOneWayFriendship;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::EntityConvertible;
use crate::storage::models::tx::transaction::TransactionEntity;
use crate::storage::models::tx::transaction_input::TransactionInputEntity;
use crate::storage::models::tx::transaction_output::TransactionOutputEntity;
use crate::util;
use crate::util::base58;
use crate::util::time::TimeUtil;

pub struct Account {
    /// BIP 43 derivation paths
    pub fund_derivation_paths: Vec<dyn IDerivationPath>,
    pub outgoing_fund_derivation_paths: Option<Vec<dyn IDerivationPath>>,
    pub default_derivation_path: Option<FundsDerivationPath>,
    pub bip44_derivation_path: Option<FundsDerivationPath>,
    pub bip32_derivation_path: Option<FundsDerivationPath>,
    pub master_contacts_derivation_path: Option<dyn IDerivationPath>,
    pub wallet: Option<&'static Wallet>,
    pub account_number: u32,
    /// current wallet balance excluding transactions known to be invalid
    pub balance: u64,
    pub balance_history: Vec<u64>,

    pub spent_outputs: HashSet<UTXO>,
    pub invalid_transaction_hashes: HashSet<UInt256>,
    pub pending_transaction_hashes: HashSet<UInt256>,
    pub pending_coinbase_locked_transaction_hashes: HashMap<u32, HashSet<UInt256>>,
    pub utxos: HashSet<UTXO>,
    // pub unspent_outputs: Vec<UTXO>,
    pub unspent_outputs: HashSet<UTXO>,
    /// latest 100 transactions sorted by date, most recent first
    pub recent_transactions: Vec<dyn ITransaction>,
    /// latest 100 transactions sorted by date, most recent first
    pub recent_transactions_with_internal_output: Vec<dyn ITransaction>,
    /// all wallet transactions sorted by date, most recent first
    pub all_transactions: Vec<dyn ITransaction>,
    /// all wallet transactions sorted by date, most recent first
    pub coinbase_transactions: Vec<CoinbaseTransaction>,
    /// Does this account have any coinbase rewards
    pub has_coinbase_transaction: bool,
    /// returns the first unused external address
    pub receive_address: Option<String>,
    /// returns the first unused internal address
    pub change_address: Option<String>,
    // /// all previously generated external addresses
    // pub external_addresses: Vec<String>,
    // /// all previously generated internal addresses
    // pub internal_addresses: Vec<String>,
    /// all the contacts for an account
    pub contacts: Vec<PotentialOneWayFriendship>,

    all_tx: HashMap<UInt256, &'static dyn ITransaction>,
    transactions: Vec<dyn ITransaction>,
    transactions_to_save: Vec<dyn ITransaction>,
    transactions_to_save_in_block_save: HashMap<u32, Vec<dyn ITransaction>>,
    contact_incoming_fund_derivation_paths_dictionary: HashMap<UInt256, IncomingFundsDerivationPath>,
    contact_outgoing_fund_derivation_paths_dictionary: HashMap<UInt256, IncomingFundsDerivationPath>,
    is_view_only_account: bool,
    // the total amount spent from the account (excluding change)
    total_sent: u64,
    // the total amount received to the account (excluding change)
    total_received: u64,
    first_transaction_hash: Option<UInt256>,
    // @property (nonatomic, readonly) NSString *uniqueID;
    context: &'static ManagedContext,
}


impl Account {

    pub fn account_with_account_number(account_number: u32, derivation_paths:Vec<FundsDerivationPath>, context: &ManagedContext) -> Self {
        Self::init_with(account_number, derivation_paths, context)
    }

    pub fn standard_accounts_to_account_number(account_number: u32, chain: &Chain, context: &ManagedContext) -> Vec<Self> {
        (0..account_number + 1)
            .map(|i|
                Self::account_with_account_number(
                    i,
                    chain.standard_derivation_paths_for_account_number(i),
                    context)).collect()
    }

    pub fn verify_derivation_path_not_already_present(&self, derivation_path: &dyn IDerivationPath) -> bool {
        // Added derivation paths should be different from existing ones on account
        self.fund_derivation_paths.iter().find(|path| derivation_path.is_derivation_path_equal(path)).is_none()
    }

    pub fn verify_and_assign_added_derivation_paths(&mut self, derivation_paths: Vec<&dyn IDerivationPath>) {
        derivation_paths.iter().enumerate().for_each(|(i, derivation_path)| {
            match derivation_path.reference() {
                DerivationPathReference::BIP32 => {
                    if self.bip32_derivation_path.is_some() {
                        assert!(true, "There should only be one BIP 32 derivation path");
                    }
                    self.bip32_derivation_path = Some(derivation_path as FundsDerivationPath);
                },
                DerivationPathReference::BIP44 => {
                    if self.bip44_derivation_path.is_some() {
                        assert!(true, "There should only be one BIP 44 derivation path");
                    }
                    self.bip44_derivation_path = Some(derivation_path as FundsDerivationPath);
                },
                DerivationPathReference::ContactBasedFundsRoot => {
                    if self.master_contacts_derivation_path.is_some() {
                        assert!(true, "There should only be one master contacts derivation path");
                    }
                    self.master_contacts_derivation_path = Some(derivation_path as DerivationPath);
                },
                _ => {}
            }
            (i+1..derivation_paths.len()).for_each(|j| {
                let derivation_path_2 = derivation_path[j];
                assert!(!derivation_path.is_derivation_path_equal(derivation_path_2), "Derivation paths should all be different");
            });
        });
    }

    pub fn init_with(account_number: u32, derivation_paths: Vec<FundsDerivationPath>, context: &ManagedContext) -> Self {
        let mut s = Self {
            account_number,
            context,
            ..Default::default()
        };
        s.verify_and_assign_added_derivation_paths(derivation_paths.iter().collect::<Vec<&FundsDerivationPath>>());
        for mut derivation_path in derivation_paths {
            s.fund_derivation_paths.push(derivation_path);
            derivation_path.base.account = Some(&s);
        }
        s
    }

    pub fn init_as_view_only_with_account_number(account_number: u32, derivation_paths: Vec<FundsDerivationPath>, context: &ManagedContext) -> Self {
        let mut s = Self::init_with(account_number, derivation_paths, context);
        s.is_view_only_account = true;
        s.transactions_to_save = vec![];
        s.transactions_to_save_in_block_save = HashMap::new();
        s
    }

    pub fn set_wallet(&mut self, wallet: &Wallet) {
        if self.wallet.is_none() {
            self.wallet = Some(wallet);
            self.load_derivation_paths();
            self.load_transactions();
        }
    }

    pub fn load_transactions(&mut self) {
        let wallet = self.wallet.unwrap();
        if wallet.is_transient {
            return;
        }
        match TransactionEntity::count_transactions_for_chain_type(wallet.chain.params.chain_type, self.context) {
            Ok(transactionCount) if transactionCount > self.all_tx.len() as i64 => {
                // pre-fetch transaction inputs and outputs
                match TransactionOutputEntity::aggregate_outputs(&wallet.unique_id_string, self.account_number, self.context) {
                    Ok(outputs) => {
                        outputs.iter().for_each(|output| {
                            let hash = output.transaction.hash;
                            if self.all_tx.get(&hash).is_none() {
                                if let Ok(tx) = Transaction::from_entity(&output.transaction, self.context) {
                                    self.all_tx.insert(hash, &tx);
                                    self.transactions.push(tx);
                                }
                            }
                            if let Some(spent_in_input) = &output.spent_in_input {
                                if let Some(spent_in_transaction) = &output.spent_in_transaction {
                                    // this has been spent, also add the transaction where it is being spent
                                    if self.all_tx.get(&hash).is_none() {
                                        if let Ok(tx) = Transaction::from_entity(spent_in_transaction, self.context) {
                                            self.all_tx.insert(hash, &tx);
                                            self.transactions.push(tx);
                                        }
                                    }
                                }
                            }
                        });
                    },
                    Err(err) => return
                }
            },
            _ => return
        }
        self.sort_transactions();
        self.balance = u64::MAX; // trigger balance changed notification even if balance is zero
        self.update_balance();
    }

    pub fn load_derivation_paths(&mut self) {
        let wallet = self.wallet.unwrap();
        if !wallet.is_transient {
            self.fund_derivation_paths.iter().for_each(|mut path| {
                if path.has_extended_public_key() {
                    path.load_addresses();
                }
            })
        } else {
            self.fund_derivation_paths.iter().for_each(|mut path| {
                let gap_limit = SequenceGapLimit::Initial;
                if path.kind() == DerivationPathKind::IncomingFunds {
                    let _ = path.register_addresses_with_gap_limit(gap_limit.dashpay(), false);
                } else {
                    let _ = path.register_addresses_with_gap_limit(gap_limit.default(), true);
                    let _ = path.register_addresses_with_gap_limit(gap_limit.default(), false);
                }
            })
        }
        if !self.is_view_only_account {
            if self.bip44_derivation_path.is_some() && self.bip44_derivation_path.unwrap().has_extended_public_key() {
                self.default_derivation_path = Some(self.bip44_derivation_path.unwrap());
            } else if self.bip32_derivation_path.is_some() && self.bip32_derivation_path.unwrap().has_extended_public_key() {
                self.default_derivation_path = Some(self.bip32_derivation_path.unwrap());
            } else if let Some(first_path) = self.fund_derivation_paths.first() {
                if first_path.kind() == DerivationPathKind::Funds {
                    self.default_derivation_path = Some(first_path as FundsDerivationPath);
                }
            }
        }
    }

    pub fn wipe_blockchain_info(&mut self) {
        self.contact_incoming_fund_derivation_paths_dictionary.values().for_each(|path| {
            if let Some(pos) = self.fund_derivation_paths.iter().position(|x| x == path) {
                self.fund_derivation_paths.remove(pos);
            }
        });
        self.contact_incoming_fund_derivation_paths_dictionary.clear();
        self.contact_outgoing_fund_derivation_paths_dictionary.clear();
        self.transactions.clear();
        self.all_tx.clear();
        self.update_balance();
    }


    /// Calculated Attributes

    pub fn unique_id(&self) -> String {
        //0 is for type 0
        format!("{}-0-{}", self.wallet.unwrap().unique_id_string, self.account_number)
    }
    pub fn block_height(&self) -> u32 {
        cmp::max(self.wallet.unwrap().chain.last_sync_block_height, 0)
    }

    /// returns the first unused external address
    pub fn receive_address(&self) -> Option<String> {
        if let Some(path) = &self.default_derivation_path {
            path.receive_address
        } else {
            None
        }
    }

    /// returns the first unused internal address
    pub fn change_address(&self) -> Option<String> {
        if let Some(path) = &self.default_derivation_path {
            path.change_address
        } else {
            None
        }
    }

    /// NSData objects containing serialized UTXOs
    pub fn unspent_outputs(&self) -> HashSet<UTXO> {
        self.unspent_outputs.clone()
    }


    /// Derivation Paths

    pub fn remove_derivation_path(&mut self, derivation_path: &dyn IDerivationPath) {
        if let Some(pos) = self.fund_derivation_paths.iter().position(|x| x == derivation_path) {
            self.fund_derivation_paths.remove(pos);
        }
    }

    pub fn remove_incoming_derivation_path_for_friendship_with_identifier(mut self, friendship_id: &UInt256) {
        if let Some(path) = self.contact_incoming_fund_derivation_paths_dictionary.get(friendship_id) {
            self.remove_derivation_path(path);
        }
    }

    pub fn derivation_path_for_friendship_with_identifier(&self, friendship_id: &UInt256) -> Option<&IncomingFundsDerivationPath> {
        self.contact_incoming_fund_derivation_paths_dictionary.get(friendship_id)
            .or(self.contact_outgoing_fund_derivation_paths_dictionary.get(friendship_id))
    }

    pub fn add_derivation_path(&mut self, derivation_path: &dyn IDerivationPath) {
        if !self.is_view_only_account {
            let path = derivation_path.clone();
            self.verify_and_assign_added_derivation_paths(vec![derivation_path.clone()]);
        }
        if self.verify_derivation_path_not_already_present(derivation_path) {
            self.fund_derivation_paths.push(derivation_path);
        }
    }

    pub fn add_incoming_derivation_path(&mut self, derivation_path: &mut IncomingFundsDerivationPath, friendship_identifier: UInt256, context: &ManagedContext) {
        assert!(!derivation_path.is_empty(), "derivation path must have a length");
        derivation_path.base.account = Some(self);
        self.add_derivation_path(derivation_path);
        self.contact_incoming_fund_derivation_paths_dictionary.insert(friendship_identifier, *derivation_path);
        if derivation_path.has_extended_public_key() {
            derivation_path.load_addresses_in_context(context);
        }
        self.update_balance();
    }

    pub fn add_outgoing_derivation_path(&mut self, derivation_path: &mut IncomingFundsDerivationPath, friendship_identifier: UInt256, context: &ManagedContext) {
        assert!(derivation_path.source_is_local || derivation_path.base.is_empty(), "derivation path must not have a length unless it is on device");
        derivation_path.base.account = Some(self);
        self.contact_outgoing_fund_derivation_paths_dictionary.insert(friendship_identifier, *derivation_path);
        if derivation_path.has_extended_public_key() {
            derivation_path.load_addresses_in_context(context);
        }
    }

    pub fn add_derivation_paths_from_array(&mut self, derivation_paths: Vec<&dyn IDerivationPath>) {
        if !self.is_view_only_account {
            self.verify_and_assign_added_derivation_paths(derivation_paths);
        }
        derivation_paths.iter().for_each(|derivation_path| {
            if self.verify_derivation_path_not_already_present(derivation_path) {
                self.fund_derivation_paths.push(derivation_path);
            }
        });
    }

    pub fn outgoing_fund_derivation_paths(&self) -> Vec<IncomingFundsDerivationPath> {
        self.contact_outgoing_fund_derivation_paths_dictionary.values().collect()
    }

    pub fn set_default_derivation_path(&mut self, path: FundsDerivationPath) {
        assert!(self.fund_derivation_paths.contains(&path), "The derivationPath is not in the account");
        self.default_derivation_path = Some(path);
    }

    pub fn derivation_path_containing_address(&self, address: Option<String>) -> Option<&dyn IDerivationPath> {
        self.fund_derivation_paths.iter().find(|path| path.contains_address(address))
    }

    /// Addresses from Combined Derivation Paths
    /// has an extended public key missing in one of the account derivation paths
    pub fn has_an_extended_public_key_missing(&self) -> bool {
        self.fund_derivation_paths.iter().find(|path| !path.has_extended_public_key()).is_some()
    }

    pub fn register_addresses_with_gap_limit(&self, gap_limit: u32, unused_account_gap_limit: u32, dashpay_gap_limit: u32, internal: bool) -> HashSet<String> {
        self.fund_derivation_paths.iter().fold(HashSet::<String>::new(), |mut arr, path| {
            match path.kind() {
                DerivationPathKind::Funds => {
                    let mut funds_derivation_path = path as FundsDerivationPath;
                    let register_gap_limit = if funds_derivation_path.should_use_reduced_gap_limit() { unused_account_gap_limit } else { gap_limit };
                    if let Ok(addresses) = funds_derivation_path.register_addresses_with_gap_limit(register_gap_limit, internal) {
                        arr.extend(addresses);
                    }
                    arr
                },
                DerivationPathKind::IncomingFunds if !internal => {
                    let mut derivation_path = path as IncomingFundsDerivationPath;
                    if let Ok(addresses) = derivation_path.register_addresses_with_gap_limit(dashpay_gap_limit, self.context()) {
                        arr.extend(addresses);
                    }
                    arr
                },
                _ => arr
            }
        })
    }

    /// all previously generated external addresses
    pub fn external_addresses(&self) -> HashSet<String> {
        let mut set: HashSet<String> = HashSet::new();
        for path in self.fund_derivation_paths {
            set.extend(path.all_receive_addresses());
        }
        set
    }

    /// all previously generated internal addresses
    pub fn internal_addresses(&self) -> HashSet<String> {
        self.fund_derivation_paths.iter().fold(HashSet::new(), |mut arr, path| {
            if path.kind() == DerivationPathKind::Funds {
                arr.extend(path.all_change_addresses());
            }
            arr
        })
    }

    pub fn all_addresses(&self) -> HashSet<String> {
        self.fund_derivation_paths.iter().fold(HashSet::new(), |mut arr, path| {
            if path.kind() == DerivationPathKind::Funds {
                arr.extend(path.all_addresses());
            }
            arr
        })
    }

    pub fn used_addresses(&self) -> HashSet<String> {
        self.fund_derivation_paths.iter().fold(HashSet::new(), |mut arr, path| {
            if path.kind() == DerivationPathKind::Funds {
                arr.extend(path.used_addresses());
            }
            arr
        })
    }

    /// true if the address is controlled by the wallet
    pub fn contains_address(&self, address: Option<String>) -> bool {
        self.fund_derivation_paths.iter().find(|path| path.contains_address(address)).is_some()
    }

    /// true if the address is controlled by the wallet
    pub fn contains_internal_address(&self, address: Option<String>) -> bool {
        self.fund_derivation_paths.iter().find(|path|
            path.kind() == DerivationPathKind::Funds &&
                (path as FundsDerivationPath).contains_change_address(address)).is_some()
    }

    pub fn base_derivation_paths_contain_address(&self, address: Option<String>) -> bool {
        self.fund_derivation_paths.iter().find(|path|
            path.kind() == DerivationPathKind::IncomingFunds &&
                path.contains_address(address)).is_some()
    }

    /// true if the address is controlled by the wallet
    pub fn contains_external_address(&self, address: Option<String>) -> bool {
        self.fund_derivation_paths.iter().find(|path|
            path.kind() == DerivationPathKind::Funds && path.contains_receive_address(address) ||
            path.kind() == DerivationPathKind::IncomingFunds && path.contains_address(address.clone())
        ).is_some()
    }

    pub fn external_derivation_path_containing_address(&self, address: Option<String>) -> Option<&IncomingFundsDerivationPath> {
        self.contact_outgoing_fund_derivation_paths_dictionary.values().find(|path| path.contains_address(address))
    }

    /// true if the address was previously used as an input or output in any wallet transaction
    pub fn address_is_used(&self, address: Option<String>) -> bool {
        self.fund_derivation_paths.iter().find(|path| path.address_is_used(address)).is_some()
    }

    pub fn transaction_address_already_seen_in_outputs(&self, address: Option<String>) -> bool {
        self.all_transactions.iter()
            .find(|tx|
                tx.outputs().iter()
                    .find(|output| output.address == address)
                    .is_some())
            .is_some()
    }

    /// Balance
    ///
    pub fn update_balance(&mut self) {
        let mut balance = 0u64;
        let mut prev_balance = 0u64;
        let total_send = 0;
        let mut total_received = 0;
        let mut utxos = HashSet::<UTXO>::new();
        let mut spent_outputs = HashSet::<>::new();
        let mut invalid_tx = HashSet::<>::new();
        let mut pending_transaction_hashes = HashSet::<>::new();
        let mut pending_coinbase_locked_transaction_hashes = HashMap::<u32, HashSet<UInt256>>::new();
        let mut balance_history = Vec::new();
        let now = SystemTime::seconds_since_1970();

        self.fund_derivation_paths.iter().for_each(|path| {
            path.balance = 0;
        });

        for tx in self.transactions.rev() {
            let mut spent = HashSet::new();
            let mut inputs: HashSet<UInt256>;
            let mut n = 0u32;
            let mut pending = false;

            if !tx.is_coinbase_classic_transaction() && tx.r#type() != TransactionType::Coinbase {
                let mut hashes = Vec::<UInt256>::new();
                tx.inputs().iter().for_each(|input| {
                    let input_hash = input.input_hash;
                    spent.insert(UTXO { hash: input_hash, n: input.index });
                    hashes.insert(0, input_hash);
                });
                inputs = HashSet::from(hashes);
                // check if any inputs are invalid or already spent
                if tx.block_height() == TX_UNCONFIRMED as u32 &&
                    (spent.intersection(&spent_outputs).count() > 0 ||
                        inputs.intersection(&invalid_tx).count() > 0) {
                    invalid_tx.insert(tx.tx_hash());
                    balance_history.insert(0, balance);
                    continue
                }
            } else {
                inputs = HashSet::new();
            }
            // add inputs to spent output set
            spent_outputs.union(&spent);
            n = 0;
            // check if any inputs are pending
            if tx.block_height() == TX_UNCONFIRMED as u32 {
                if tx.size() > TX_MAX_SIZE {
                    // check transaction size is under TX_MAX_SIZE
                    pending = true;
                }
                for input in tx.inputs() {
                    if input.sequence == u32::MAX {
                        continue;
                    }
                    if tx.lock_time() < TX_MAX_LOCK_HEIGHT &&
                        tx.lock_time() > self.wallet.unwrap().chain.best_block_height + 1 {
                        pending = true; // future lockTime
                    }
                    if tx.lock_time() >= TX_MAX_LOCK_HEIGHT && tx.lock_time() > now {
                        pending = true; // future lockTime
                    }
                }
                // check that no outputs are dust
                for output in tx.outputs() {
                    if output.amount < TX_MIN_OUTPUT_AMOUNT {
                        pending = true;
                    }
                }
            }
            if pending || inputs.intersection(&pending_transaction_hashes).count() > 0 {
                pending_transaction_hashes.insert(tx.tx_hash());
                balance_history.insert(0, balance);
                continue;
            }
            let locked_block_height: u32 = self.transaction_outputs_are_locked_till(tx);

            if locked_block_height != 0 {

                if !pending_coinbase_locked_transaction_hashes.contains(&locked_block_height) {
                    pending_coinbase_locked_transaction_hashes.insert(locked_block_height, HashSet::new());
                }
                pending_coinbase_locked_transaction_hashes.get(&locked_block_height).unwrap().insert(tx.tx_hash());
                balance_history.insert(0, balance);
                continue;
            }

            // TODO: don't add outputs below TX_MIN_OUTPUT_AMOUNT
            // TODO: don't add coin generation outputs < 100 blocks deep
            // NOTE: balance/UTXOs will then need to be recalculated when last block changes
            for output in tx.outputs() {
                for derivation_path in self.fund_derivation_paths {
                    if derivation_path.contains_address(output.address) {
                        if derivation_path.kind() == DerivationPathKind::Funds {
                            (derivation_path as FundsDerivationPath).set_has_known_balance();
                        }
                    }
                    let amount = output.amount;
                    derivation_path.balance += amount;
                    utxos.insert(UTXO { hash: tx.tx_hash(), n });
                    balance += amount;
                }
                n += 1;
            }
            // transaction ordering is not guaranteed, so check the entire UTXO set against the entire spent output set
            spent = utxos.clone();
            spent = inplace_intersection(&mut spent, &mut spent_outputs);

            // remove any spent outputs from UTXO set
            for o in spent {
                let transaction = self.all_tx.get(&o.hash);
                utxos.remove(&o);
                let output = transaction.unwrap().outputs().get(&o.n);
                let amount = output.amount;
                balance -= amount;
                for derivation_path in self.fund_derivation_paths {
                    if derivation_path.contains_address(output.address) {
                        derivation_path.balance -= amount;
                        break;
                    }
                }
            }
            if prev_balance < balance {
                total_received += balance - prev_balance;
            }
            if balance < prev_balance {
                total_sent += prev_balance - balance;
            }
            balance_history.insert(0, balance);
            prev_balance = balance;
        }
        self.invalid_transaction_hashes = invalid_tx;
        self.pending_transaction_hashes = pending_transaction_hashes;
        self.pending_coinbase_locked_transaction_hashes = pending_coinbase_locked_transaction_hashes;
        self.spent_outputs = spent_outputs;
        self.utxos = utxos;
        self.balance_history = balance_history;
        self.total_sent = total_sent;
        self.total_received = total_received;

        if balance != self.balance {
            self.balance = balance;
            DispatchContext::main_context().queue(||
                NotificationCenter::post(Notification::WalletBalanceDidChange))
            // dispatch_async(dispatch_get_main_queue(), ^{
            //     [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(postBalanceDidChangeNotification) object:nil];
            //     [self performSelector:@selector(postBalanceDidChangeNotification) withObject:nil afterDelay:0.1];
            // });
        }
    }

    /// historical wallet balance after the given transaction, or current balance if transaction is not registered in wallet
    pub fn balance_after_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        if let Some(pos) = self.transactions.iter().position(|x| x == transaction) {
            if pos < self.balance_history.len() {
                return *self.balance_history.get(pos).unwrap();
            }
        }
        self.balance
    }

    /// Transactions

    /// Helpers

    /// chain position of first tx output address that appears in chain
    pub fn transaction_address_index(transaction: &dyn ITransaction, address_chain: HashSet<String>) -> Option<usize> {
        transaction.outputs()
            .iter()
            .find_map(|output|
                address_chain.iter()
                    .position(|a| a == output.address))
    }

    #[Inline]
    fn is_ascending(&self, tx1: &dyn ITransaction, tx2: &dyn ITransaction) -> bool {
        // if (!tx1 || !tx2) return NO;
        if tx1.block_height() > tx2.block_height() {
            return true;
        }
        if tx1.block_height() < tx2.block_height() {
            return false;
        }
        let hash1 = tx1.tx_hash();
        let hash2 = tx2.tx_hash();
        if let Some(pos) = tx1.inputs().iter().position(|input| input.input_hash == hash2) {
            return true;
        }
        if let Some(pos) = tx2.inputs().iter().position(|input| input.input_hash == hash1) {
            return false;
        }
        if self.invalid_transaction_hashes.contains(&hash1) && !self.invalid_transaction_hashes.contains(&hash2) {
            return true;
        }
        if self.pending_transaction_hashes.contains(&hash1) && !self.pending_transaction_hashes.contains(&hash2) {
            return true;
        }
        for input in tx1.inputs() {
            if let Some(tx) = self.all_tx.get(&input.input_hash) {
                if self.is_ascending(tx, tx2) {
                    return true;
                }
            }
        }
        return false;
    }

    // this sorts transactions by block height in descending order, and makes a best attempt at
    // ordering transactions within each block, however correct transaction ordering cannot be
    // relied upon for determining wallet balance or UTXO set
    pub fn sort_transactions(&mut self) {
        self.transactions.sort_by(|tx1, tx2| {
            if self.is_ascending(tx1, tx2) {
                Ordering::Greater
            } else if self.is_ascending(tx2, tx1) {
                Ordering::Less
            } else {
                let mut i = Self::transaction_address_index(tx1, self.internal_addresses());
                let j = Self::transaction_address_index(tx2, if i.is_none() { self.external_addresses() } else { self.internal_addresses() });
                if i.is_none() && j.is_some() {
                    i = Self::transaction_address_index(tx1, self.external_addresses());
                }
                if i.is_none() || j.is_none() || i == j {
                    return Ordering::Equal;
                }
                i.unwrap().cmp(&j.unwrap())
            }
        });
    }

    /// Retrieval

    /// Classical Transaction Retrieval

    /// returns the transaction with the given hash if it's been registered in the wallet (might also return non-registered)
    pub fn transaction_for_hash(&self, hash: &UInt256) -> Option<&dyn ITransaction> {
        self.all_tx.get(hash)
    }

    /// last 100 transactions sorted by date, most recent first
    pub fn recent_transactions(&self) -> Vec<&dyn ITransaction> {
        self.transactions[0..min(100, self.transactions.len())].iter().cloned().collect()
    }

    /// last 100 transactions sorted by date, most recent first
    pub fn recent_transactions_with_internal_output(&self) -> Vec<&dyn ITransaction> {
        let mut recent_transaction_array = Vec::<&dyn ITransaction>::new();
        let mut i = 0;
        while recent_transaction_array.len() < 100 && i < self.transactions.len() {
            if let Some(transaction) = self.transactions.get(i) {
                if transaction.has_non_dust_output_in_wallet(self.wallet.unwrap()) {
                    recent_transaction_array.push(transaction);
                }
            }
            i += 1;
        }
        recent_transaction_array
    }

    /// all wallet transactions sorted by date, most recent first
    pub fn all_transactions(&self) -> &Vec<dyn ITransaction> {
        &self.transactions
    }

    /// all wallet transactions sorted by date, most recent first
    pub fn coinbase_transactions(&self) -> &Vec<dyn ITransaction> {
        self.transactions.iter().filter(|tx| tx.r#type() == TransactionType::Coinbase).collect()
    }

    /// Does this account have any rewards
    pub fn has_coinbase_transaction(&self) -> bool {
        self.transactions.iter().find(|tx| tx.r#type() == TransactionType::Coinbase).is_some()
    }


    /// Existence

    /// true if the given transaction is associated with the account (even if it hasn't been registered), false otherwise
    pub fn can_contain_transaction(&self, transaction: &dyn ITransaction) -> bool {
        assert!(transaction.is_some());
        let output_addresses = transaction.output_addresses();
        let out_set = HashSet::from(output_addresses);
        if self.all_addresses().intersection(&HashSet::from(&output_addresses)).count() > 0 {
            return true;
        }
        for input in transaction.inputs() {
            if let Some(tx) = self.all_tx.get(&input.input_hash) {
                let n = input.index as usize;
                let outputs = tx.outputs();
                if n < outputs.len() && self.contains_address(outputs.get(n).unwrap().address.clone()) {
                    return true;
                }
            }
        }
        match transaction.r#type() {
            TransactionType::ProviderRegistration => {
                let provider_registration_transaction = transaction as ProviderRegistrationTransaction;
                if self.contains_address(provider_registration_transaction.payout_address()) {
                    return true;
                }
            },
            TransactionType::ProviderUpdateService => {
                let mut provider_update_service_transaction = transaction as ProviderUpdateServiceTransaction;
                let payout_address_opt = provider_update_service_transaction.payout_address();
                if let Some(payout_address) = payoout_address_opt {
                    if self.contains_address(payout_address_opt) {
                        return true;
                    }
                }
            },
            TransactionType::ProviderUpdateRegistrar => {
                let mut provider_update_registrar_transaction = transaction as ProviderUpdateRegistrarTransaction;
                if self.contains_address(provider_update_registrar_transaction.payout_address()) {
                    return true;
                }
            },
            _ => {}
        }
        false
    }

    pub fn check_is_first_transaction(&self, transaction: &dyn ITransaction) -> bool {
        for derivation_path in &self.fund_derivation_paths {
            let kind = derivation_path.kind();
            if kind & DerivationPathType::IsForFunds != 0 {
                let mut first_address: Option<String> = None;
                if kind == DerivationPathKind::Funds {
                    first_address = (derivation_path as FundsDerivationPath).address_at_index(0, false);
                } else if kind == DerivationPathKind::IncomingFunds {
                    first_address = (derivation_path as IncomingFundsDerivationPath).address_at_index(0);
                }
                if first_address.is_some() {
                    if transaction.outputs().iter().position(|o| o.address == first_address).is_some() {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// Creation

    /// returns an unsigned transaction that sends the specified amount from the wallet to the given address
    pub fn transaction_for(&mut self, amount: u64, address: String, with_fee: bool) -> Option<&dyn ITransaction> {
        if let Some(wallet) = self.wallet {
            let script = Vec::<u8>::script_pub_key_for_address(&address, wallet.chain);
            self.transaction_for_amounts(vec![amount],  vec![script], with_fee)
        } else {
            None
        }
    }

    /// returns an unsigned transaction that sends the specified amount from the wallet to the given address
    pub fn credit_funding_transaction_for(&mut self, amount: u64, address: String, with_fee: bool) -> Option<&CreditFundingTransaction> {
        if let Some(wallet) = self.wallet {
            let script = Vec::<u8>::credit_burn_script_pub_key_for_address(&address, wallet.chain);
            let tx = CreditFundingTransaction { base: Transaction::init_on_chain(wallet.chain), ..Default::default() };
            self.update_transaction_with_sort_type(&tx, vec![amount], vec![script], with_fee, TransactionSortType::BIP69)
        } else {
            None
        }

    }

    /// returns an unsigned transaction that sends the specified amounts from the wallet to the specified output scripts
    pub fn transaction_for_amounts(&mut self, amounts: Vec<u64>, output_scripts: Vec<Vec<u8>>, with_fee: bool) -> Option<&dyn ITransaction> {
        self.transaction_for_amounts_to_shapeshift_address(amounts, output_scripts, with_fee, None)
    }

    pub fn transaction_for_amounts_to_shapeshift_address(&mut self, amounts: Vec<u64>, output_scripts: Vec<Vec<u8>>, with_fee: bool, shapeshift_address: Option<String>) -> Option<&dyn ITransaction> {
        let tx = Transaction::init_on_chain(self.wallet.unwrap().chain);
        self.update_transaction_with_sort_type_to_shapeshift_address(&tx, amounts, output_scripts, with_fee, shapeshift_address, TransactionSortType::BIP69)
    }

    /// Proposal Transaction Creation
    pub fn proposal_collateral_transaction_with_data(&mut self, data: Vec<u8>) -> Option<&dyn ITransaction> {
        let script = Vec::<u8>::proposal_info(data);
        self.transaction_for_amounts(vec![PROPOSAL_COST], vec![script], true)
    }

    /// Update

    /// returns an unsigned transaction that sends the specified amounts from the wallet to the specified output scripts
    pub fn update_transaction(&mut self, transaction: &dyn ITransaction, amounts: Vec<u64>, output_scripts: Vec<Vec<u8>>, with_fee: bool) -> Option<&dyn ITransaction> {
        self.update_transaction_with_sort_type(transaction, amounts, output_scripts, with_fee, TransactionSortType::BIP69)
    }

    pub fn update_transaction_with_sort_type(&mut self, transaction: &dyn ITransaction, amounts: Vec<u64>, output_scripts: Vec<Vec<u8>>, with_fee: bool, sort_type: TransactionSortType) -> Option<&dyn ITransaction> {
        self.update_transaction_with_sort_type_to_shapeshift_address(transaction, amounts, output_scripts, with_fee, None, sort_type)
    }

    /// returns an unsigned transaction that sends the specified amounts from the wallet to the specified output scripts
    pub fn update_transaction_with_sort_type_to_shapeshift_address(&mut self, transaction: &dyn ITransaction, amounts: Vec<u64>, output_scripts: Vec<Vec<u8>>, with_fee: bool, shapeshift_address: Option<String>, sort_type: TransactionSortType) -> Option<&dyn ITransaction> {
        let mut amount = 0u64;
        let mut balance = 0u64;
        let mut fee_amount = 0u64;
        let mut fee_amount_without_change = 0u64;

        let mut i = 0;
        let mut cpfp_size = 0;
        // DSTransaction *tx;
        // NSUInteger i = 0, cpfpSize = 0;
        // DSUTXO o;
        if amounts.len() != output_scripts.len() /*|| amounts.len() < 1*/ {
            return None; // sanity check
        }

        for script in output_scripts {
            if script.is_empty() {
                return None;
            }
            transaction.add_output_script(script, amounts[i]);
            amount += amounts[i];
            i += 1;
        }

        // TODO: use up all UTXOs for all used addresses to avoid leaving funds in addresses whose public key is revealed
        // TODO: avoid combining addresses in a single transaction when possible to reduce information leakage
        // TODO: use up UTXOs received from any of the output scripts that this transaction sends funds to, to mitigate an
        //      attacker double spending and requesting a refund
        for o in self.utxos {
            if let Some(tx) = self.all_tx.get(&o.hash) {
                if self.transaction_outputs_are_locked(tx) {
                    continue;
                }
                if transaction.r#type() == TransactionType::ProviderRegistration {
                    let provider_registration_transaction = transaction as ProviderRegistrationTransaction;
                    if provider_registration_transaction.collateral_outpoint == o {
                        // don't spend the collateral
                        continue;
                    }
                    let reversed_collateral = UTXO {
                        hash: provider_registration_transaction.collateral_outpoint.hash.clone().reversed(),
                        n: provider_registration_transaction.collateral_outpoint.n
                    };
                    if reversed_collateral == o {
                        // don't spend the collateral
                        continue
                    }
                }
                transaction.add_input_hash(tx.tx_hash(), o.n, tx.outputs[o.n].out_script);
                if transaction.size() as u64 + TX_OUTPUT_SIZE > TX_MAX_SIZE {
                    // transaction size-in-bytes too large
                    let tx_size = 10 + self.utxos.len() * 148 + (output_scripts.len() + 1) * TX_OUTPUT_SIZE;
                    // check for sufficient total funds before building a smaller transaction
                    if self.balance < amount + self.wallet.unwrap().chain.fee_for_tx_size(tx_size + cpfp_size) {
                        println!("Insufficient funds. {} is less than transaction amount: {}", self.balance, amount + self.wallet.unwrap().chain.fee_for_tx_size(tx_size + cpfp_size));
                        return None;
                    }
                    let last_amount = amounts.last().unwrap();
                    // todo: check array bounds
                    let mut new_amounts = Vec::from(amounts[0..amounts.len() - 1]);
                    let mut new_scripts = Vec::from(outputs_scripts[0..outputs_scripts.len() - 1]);
                    if last_amount > amount + fee_amount + self.wallet.unwrap().chain.min_output_amount - balance {
                        // reduce final output amount
                        new_amounts.push(last_amount - (amount + fee_amount - balance));
                        new_scripts.push(output_scripts.last().unwrap().clone());
                    }
                    return self.transaction_for_amounts(new_amounts, new_scripts, with_fee);
                }
                balance += tx.outputs[o.n].amount;
                // add up size of unconfirmed, non-change inputs for child-pays-for-parent fee calculation
                // don't include parent tx with more than 10 inputs or 10 outputs
                if tx.block_height() == TX_UNCONFIRMED && tx.inputs.len() <= 10 && tx.outputs.len() <= 10 && self.amount_sent_by_transaction(tx) == 0 {
                    cpfp_size += tx.size();
                }
                if with_fee {
                    fee_amount_without_change = self.wallet.unwrap().chain.fee_for_tx_size(transaction.size() + cpfp_size);
                    if balance == amount + fee_amount_without_change {
                        fee_amount = fee_amount_without_change;
                        break;
                    }
                    // assume we will add a change output
                    fee_amount = self.wallet.unwrap().chain.fee_for_tx_size(transaction.size() + TX_OUTPUT_SIZE + cpfp_size)
                }

                if balance == amount + fee_amount || balance >= amount + fee_amount + self.wallet.chain.min_output_amount {
                    break;
                }
            } else {
                continue;
            }
        }
        if fee_amount == 0 {
            // assume we will add a change output
            fee_amount = self.wallet.unwrap().chain.fee_for_tx_size(transaction.size() + TX_OUTPUT_SIZE + cpfp_size);
        }
        if balance < amount + fee_amount {
            // insufficient funds
            println!("Insufficient funds. {} is less than transaction amount: {}", balance, amount + fee_amount);
            return None;
        }
        if let Some(shapeshift_address) = shapeshift_address {
            transaction.add_output_shapeshift_address(shapeshift_address);
        }
        let follow_bip69_sorting = sort_type == TransactionSortType::BIP69;
        if follow_bip69_sorting {
            transaction.sort_inputs_according_to_bip69();
        }
        if balance - (amount + fee_amount) >= self.wallet.unwrap().chain.min_output_amount {
            transaction.add_output_address(self.change_address(), balance - (amount + fee_amount));
            if follow_bip69_sorting {
                transaction.sort_outputs_according_to_bip69();
            } else if sort_type == TransactionSortType::Shuffle {
                transaction.shuffle_output_order();
            }
        }
        transaction.has_set_inputs_and_outputs();
        Some(transaction)
    }

    pub fn chain_updated_block_height(&mut self, height: u32) {
        if self.pending_coinbase_locked_transaction_hashes.contains_key(&height) {
            self.update_balance();
        }
    }

    /// set the block heights and timestamps for the given transactions, use a height of TX_UNCONFIRMED and timestamp of 0 to
    /// indicate a transaction and it's dependents should remain marked as unverified (not 0-conf safe)
    pub fn set_block_height(&mut self, height: u32, timestamp: u64, transaction_hashes: &Vec<UInt256>) -> Vec<UInt256> {
        let mut hashes = Vec::<UInt256>::new();
        let mut updated = Vec::<UInt256>::new();
        let mut needs_update = false;
        let wallet_creation_time = self.wallet.unwrap().wallet_creation_time();
        for h in transaction_hashes {
            if let Some(tx) = self.all_tx.get(&h) {
                if tx.block_height() == height && tx.timestamp() == timestamp {
                    continue;
                }
                tx.block_height = height;
                if tx.timestamp() == u32::MAX || tx.timestamp() == 0 {
                    // We should only update the timestamp one time
                    tx.timestamp = timestamp;
                }
                if self.can_contain_transaction(tx) {
                    hashes.push(h.clone());
                    updated.push(h.clone());
                    if (wallet_creation_time == BIP39_WALLET_UNKNOWN_CREATION_TIME || wallet_creation_time == BIP39_CREATION_TIME) && h == self.first_transaction_hash {
                        self.wallet.unwrap().set_guessed_wallet_creation_time(tx.timestamp() - HOUR_TIME_INTERVAL - (DAY_TIME_INTERVAL / thread_rng().gen::<u64>() % DAY_TIME_INTERVAL));
                    }
                    if self.pending_transaction_hashes.contains(&h) || self.invalid_transaction_hashes.contains(&h) {
                        needs_update = true;
                    } else if height != TX_UNCONFIRMED {
                        self.all_tx.remove(&h); // remove confirmed non-wallet tx
                    }
                }
            }
        }
        if !hashes.is_empty() && needs_update {
            self.sort_transactions();
            self.update_balance();
        }
        return updated;
    }

    /// Removal

    /// removes a transaction from the wallet along with any transactions that depend on its outputs
    pub fn remove_transaction_with_hash(&self, tx_hash: &UInt256, save_immediately: bool) -> bool {
        if let Some(tx) = self.all_tx.get(tx_hash) {
            tx.remove_transaction(transaction, save_immediately)
        } else {
            false
        }
    }

    pub fn remove_transaction(&mut self, base_transaction: &dyn ITransaction, save_immediately: bool) -> bool {
        let mut dependent_transactions = HashSet::new();
        if let Some(transaction) = self.all_tx.get(&base_transaction.tx_hash()) {
            let transaction_hash = transaction.tx_hash();
            // remove dependent transactions
            for possible_dependent_tx in self.transactions {
                if possible_dependent_tx.block_height() < transaction.block_height() {
                    // because transactions are sorted we can break
                    break;
                }
                if transaction_hash != possible_dependent_tx.tx_hash() &&
                    possible_dependent_tx.inputs().iter().position(|input| input.input_hash == transaction_hash).is_some() {
                    // this transaction is dependent on one we want to remove
                    dependent_transactions.insert(possible_dependent_tx);
                }
            }

            for transaction in dependent_transactions {
                // remove all dependent transactions
                self.remove_transaction(transaction, false);
            }
            self.all_tx.remove(transaction);
            if let Some(pos) = self.transactions.iter().position(|tx| tx == transaction) {
                self.transactions.remove(pos);
            }
            self.update_balance();
            // todo: check if needed
            // if save_immediately {}
            TransactionEntity::delete_with_tx_hash(&transaction_hash, self.context)
                .expect("Can't delete transactions");
            // [self.managedObjectContext performBlockAndWait:^{
            //     [DSTransactionHashEntity deleteObjects:[DSTransactionHashEntity objectsInContext:self.managedObjectContext matching:@"txHash == %@", [NSData dataWithUInt256:transactionHash]] inContext:self.managedObjectContext];
            //     if (saveImmediately) {
            //         [self.managedObjectContext ds_save];
            //     }
            // }];
            true

        } else {
            false
        }
    }

    /// Signing

    /// sign any inputs in the given transaction that can be signed using private keys from the wallet
    pub fn sign_transaction(&self, transaction: &dyn ITransaction, authprompt: Option<String>, completion: fn(bool, bool)) {
        if self.is_view_only_account {
            return;
        }
        let mut used_derivation_paths = Vec::<(dyn IDerivationPath, HashSet<u32>, HashSet<u32>)>::new();
        let amount = self.amount_sent_by_transaction(transaction) - self.amount_received_from_transaction(transaction);
        for derivation_path in self.fund_derivation_paths {
            let mut external_indexes = HashSet::<u32>::new();
            let mut internal_indexes = HashSet::<u32>::new();
            for address in transaction.input_addresses() {
                if !(derivation_path.r#type() == DerivationPathType::ClearFunds ||
                    derivation_path.r#type() == DerivationPathType::AnonymousFunds) {
                    continue;
                }
                if derivation_path.kind() == DerivationPathKind::Funds {
                    let derivation_path = derivation_path as FundsDerivationPath;
                    if let Some(index) = derivation_path.all_change_addresses().iter().position(|a| a == address) {
                        internal_indexes.insert(index as u32);
                        continue;
                    }
                }
                if let Some(index) = derivation_path.all_receive_addresses().iter().position(|a| a == address) {
                    external_indexes.insert(index as u32);
                    continue;
                }
            }
            if !external_indexes.is_empty() || !internal_indexes.is_empty() {
                used_derivation_paths.push((derivation_path, external_indexes, internal_indexes));
            }
        }
        let seed_completion: SeedCompletionBlock = |seed, cancelled| {
            if seed.is_none() {
                completion(false, true);
            } else {
                let mut privkeys = Vec::<dyn IKey>::new();
                used_derivation_paths.iter().for_each(|(derivation_path, external_indexes, internal_indexes)| {
                    if derivation_path.kind() == DerivationPathKind::Funds {
                        let path = derivation_path as FundsDerivationPath;
                        privkeys.extend(path.private_keys(external_indexes.iter().collect(), false, seed));
                        privkeys.extend(path.private_keys(internal_indexes.iter().collect(), true, seed.clone()));
                    } else if derivation_path.kind() == DerivationPathKind::IncomingFunds {
                        let path = derivation_path as IncomingFundsDerivationPath;
                        privkeys.extend(path.private_keys(external_indexes.iter().collect(), seed));
                    } else {
                        assert!(false, "The derivation path must be a normal or incoming funds derivation path");
                    }
                });
                let signed_successfully = transaction.sign_with_private_keys(privkeys);
                completion(signed_successfully, false);
            }
        };
        self.wallet.unwrap().seed_request_block.unwrap()(authprompt, cmp::max(amount, 0), Some(seed_completion));
    }

    /// sign any inputs in the given transaction that can be signed using private keys from the wallet
    pub fn sign_transactions(&self, transactions: Vec<&dyn ITransaction>, authprompt: Option<String>, completion: fn(bool, bool)) {
        if self.is_view_only_account {
            return;
        }
        let amount = transactions.iter().map(|tx| self.amount_sent_by_transaction(tx) - self.amount_received_from_transaction(tx)).sum();
        let seed_completion: SeedCompletionBlock = |seed, cancelled| {
            for transaction in transactions {
                let mut used_derivation_paths = Vec::<(&dyn IDerivationPath, HashSet<u32>, HashSet<u32>)>::new();
                for derivation_path in self.fund_derivation_paths {
                    let mut external_indexes = HashSet::<u32>::new();
                    let mut internal_indexes = HashSet::<u32>::new();
                    for address in transaction.input_addresses() {
                        if !(derivation_path.r#type() == DerivationPathType::ClearFunds || derivation_path.r#type() == DerivationPathType::AnonymousFunds) {
                            continue;
                        }
                        if let Some(index) = derivation_path.all_change_addresses().iter().position(|a| a == address) {
                            internal_indexes.insert(index);
                            continue;
                        }
                        if let Some(index) = derivation_path.all_rececive_addresses().iter().position(|a| a == address) {
                            external_indexes.insert(index);
                            continue;
                        }
                    }
                    used_derivation_paths.push((derivation_path, external_indexes, internal_indexes));
                }
                if seed.is_none() {
                    completion(false, cancelled);
                } else {
                    let mut privkeys = Vec::<dyn IKey>::new();
                    used_derivation_paths.iter().for_each(|(derivation_path, external_indexes, internal_indexes)| {
                        privkeys.extend(derivation_path.serialized_private_keys(external_indexes, false, seed.clone()));
                        privkeys.extend(derivation_path.serialized_private_keys(internal_indexes, true, seed.clone()));
                    });
                    let signed_successfully = transaction.sign_with_serialized_private_keys(privkeys);
                    completion(signed_successfully, false);
                }
            }
        };
        self.wallet.unwrap().seed_request_block.unwrap()(authprompt, cmp::max(amount, 0), Some(seed_completion));
    }

    /// Registration

    /// records the transaction in the account, or returns false if it isn't associated with the wallet
    pub fn register_transaction(&mut self, transaction: &dyn ITransaction, save_immediately: bool) -> bool {
        let hash = transaction.tx_hash();
        if hash.is_zero() {
            return false;
        }
        if !self.can_contain_transaction(transaction) {
            // this transaction is not meant for this account
            if transaction.block_height() == TX_UNCONFIRMED {
                if self.check_is_first_transaction(transaction) {
                    // it's okay if this isn't really the first, as it will be close enough (500 blocks close)
                    self.first_transaction_hash = Some(hash);
                }
                self.all_tx.insert(hash, transaction);
            }
            return false;
        }
        if self.all_tx.get(&hash).is_some() {
            return true;
        }

        // TODO: handle tx replacement with input sequence numbers (now replacements appear invalid until confirmation)
        if self.check_is_first_transaction(transaction) {
            // it's okay if this isn't really the first, as it will be close enough (500 blocks close)
            self.first_transaction_hash = Some(hash);
        }
        self.all_tx.insert(hash, transaction);
        self.transactions.insert(0, transaction);

        transaction.input_addresses()
            .iter()
            .for_each(|address|
                self.fund_derivation_paths
                    .iter()
                    .for_each(|mut path| {
                        // only will register if derivation path contains address
                        path.register_transaction_address(address);
                    }));

        transaction.outputs()
            .iter()
            .for_each(|output|
                self.fund_derivation_paths
                    .iter()
                    .for_each(|mut path| {
                        // only will register if derivation path contains address
                        if let Some(address) = &output.address {
                            path.register_transaction_address(address)
                        }
                    }));
        transaction.load_identities_from_derivation_paths(&self.fund_derivation_paths);
        transaction.load_identities_from_derivation_paths(&self.outgoing_fund_derivation_paths());
        self.update_balance();
        if saveImmediately {
            if !self.wallet.unwrap().is_transient {
                transaction.save_initial();
            }
        } else {
            self.transactions_to_save.push(transaction);
        }
        true
    }

    pub fn prepare_for_incoming_transaction_persistence_for_block_save_with_number(&mut self, block_number: u32) {
        self.transactions_to_save_in_block_save.insert(block_number, self.transactions_to_save.clone());
        self.transactions_to_save.clear();
    }

    pub fn persist_incoming_transactions_attributes_for_block_save_with_number(&mut self, block_number: u32, context: &ManagedContext) {
        if let Some(transactions) = self.transactions_to_save_in_block_save.get(&block_number) {
            transaction.iter().for_each(|tx| tx.set_initial_persistent_attributes_in_context(context));
            self.transactions_to_save_in_block_save.remove(&block_number);
        }
    }


    /// Transaction State

    /// true if no previous wallet transactions spend any of the given transaction's inputs, and no input tx is invalid
    pub fn transaction_is_valid(&self, transaction: &dyn ITransaction) -> bool {
        // TODO: XXX attempted double spends should cause conflicted tx to remain unverified until they're confirmed
        // TODO: XXX verify signatures for spends
        if transaction.blockHeight != TX_UNCONFIRMED {
            return true;
        }
        let tx_hash = transaction.tx_hash();
        if let Some(tx) = self.all_tx.get(&tx_hash) {
            return !self.invalid_transaction_hashes.contains(&tx_hash);
        }
        for input in transaction.inputs() {
            let hash = input.input_hash;
            let n = input.index;
            let tx = self.all_tx.get(&hash);
            if (tx.is_some() && !self.transaction_is_valid(tx.unwrap())) || self.spent_outputs.contains(&UTXO { hash, n }) {
                return false;
            }
        }
        true
    }

    /// true if transaction cannot be immediately spent (i.e. if it or an input tx can be replaced-by-fee)
    pub fn transaction_is_pending(&self, transaction: &dyn ITransaction) -> bool {
        // confirmed transactions are not pending
        if transaction.block_height() != TX_UNCONFIRMED {
            return false;
        }
        // check transaction size is under TX_MAX_SIZE
        if transaction.size() as u64 > TX_MAX_SIZE {
            return true;
        }
        let lock_time = transaction.lock_time();
        // check for future lockTime or replace-by-fee: https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
        for input in transaction.inputs() {
            if input.sequence >= u32::MAX {
                continue;
            }
            if lock_time < TX_MAX_LOCK_HEIGHT && lock_time > self.wallet.unwrap().chain.best_block_height + 1 {
                return true;
            }
            if lock_time >= TX_MAX_LOCK_HEIGHT && lock_time > SystemTime::seconds_since_1970() {
                return true;
            }
        }
        // check that no outputs are dust
        for output in transaction.outputs() {
            if output.amount < TX_MIN_OUTPUT_AMOUNT {
                return true;
            }
        }
        // check if any inputs are known to be pending
        for input in transaction.inputs() {
            let tx_hash = input.input_hash;
            if let Some(tx) = self.all_tx.get(&tx_hash) {
                if self.transaction_is_pending(tx) {
                    return true;
                }
            }
        }
        false
    }

    pub fn transaction_outputs_are_locked(&mut self, transaction: &dyn ITransaction) -> bool {
        self.transaction_outputs_are_locked_till(transaction) != 0
    }

    /// true if this transaction outputs can not be used in inputs
    pub fn transaction_outputs_are_locked_till(&mut self, transaction: &dyn ITransaction) -> u32 {
        if transaction.kind() == TransactionType::Coinbase {
            // only allow these to be spent after 100 inputs
            let coinbase_transaction = transaction as CoinbaseTransaction;
            if coinbase_transaction.height + 100 > self.wallet.unwrap().last_sync_block_height() {
                return coinbase_transaction.height + 100;
            }
        }
        0
    }

    /// true if tx is considered 0-conf safe (valid and not pending, timestamp is greater than 0, and no unverified inputs)
    pub fn transaction_is_verified(&self, transaction: &dyn ITransaction) -> bool {
        assert!(transaction);
        if transaction.block_height() != TX_UNCONFIRMED {
            // confirmed transactions are always verified
            return true;
        }
        if transaction.timetamp() == 0 {
            // a timestamp of 0 indicates transaction is to remain unverified
            return false;
        }
        if !self.transaction_is_valid(transaction) || self.transaction_is_pending(transaction) {
            return false;
        }
        for input in transaction.inputs() {
            // check if any inputs are known to be unverfied
            if let Some(tx) = self.all_tx.get(&input.input_hash) {
                if !self.transaction_is_verified(tx) {
                    return false;
                }
            }
        }
        true
    }

    /// Direction
    pub fn direction_of_transaction(&self, transaction: &dyn ITransaction) -> TransactionDirection {
        let sent = self.amount_sent_by_transaction(transaction);
        let received = self.amount_received_from_transaction(transaction);
        let fee = transaction.fee_used;
        if sent > 0 && received + fee == sent {
            TransactionDirection::Moved
        } else if sent > 0 {
            TransactionDirection::Sent
        } else if received > 0 {
            TransactionDirection::Received
        } else {
            TransactionDirection::NotAccountFunds
        }
    }


    /// Amounts


    /// returns the amount received by the wallet from the transaction (total outputs to change and/or receive addresses)
    pub fn amount_received_from_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        // TODO: don't include outputs below TX_MIN_OUTPUT_AMOUNT
        transaction.outputs()
            .iter()
            .filter_map(|output|
                if output.address.is_some() && self.contains_address(output.address.clone()) { Some(output.amount) } else { None })
            .sum()
    }

    pub fn amount_received_from_transaction_on_external_addresses(&self, transaction: &dyn ITransaction) -> u64 {
        // TODO: don't include outputs below TX_MIN_OUTPUT_AMOUNT
        transaction.outputs()
            .iter()
            .filter_map(|output|
                if output.address.is_some() && self.contains_external_address(output.address.clone()) { Some(output) } else { None })
            .sum()
    }

    pub fn amount_received_from_transaction_on_internal_addresses(&self, transaction: &dyn ITransaction) -> u64 {
        // TODO: don't include outputs below TX_MIN_OUTPUT_AMOUNT
        transaction.outputs()
            .iter()
            .filter_map(|output|
                if output.address.is_some() && self.contains_internal_address(output.address.clone()) { Some(output) } else { None })
            .sum()
    }

    /// returns the amount sent from the wallet by the trasaction (total wallet outputs consumed, change and fee included)
    pub fn amount_sent_by_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        transaction.inputs().iter().filter_map(|input| {
            if let Some(tx) = self.all_tx.get(&input.input_hash) {
                let n = input.index as usize;
                let outputs = tx.outputs();
                if let Some(output) = outputs.get(n) {
                    if n < outputs.len() && self.contains_address(output.address.clone()) {
                        Some(output.amount)
                    }
                }
            }
            None
        }).sum()
    }

    /// Addresses
    pub fn external_addresses_of_transaction(&self, transaction: &dyn ITransaction) -> Vec<&String> {
        transaction.outputs().iter().fold(Vec::<&String>::new(), |mut addresses, output| {
            if let Some(address) = &output.address {
                if transaction.r#type() == TransactionType::ProviderRegistration &&
                    (transaction as ProviderRegistrationTransaction).masternode_holding_wallet.contains_holding_address(address) {
                    let sent = self.amount_sent_by_transaction(transaction);
                    let received = self.amount_received_from_transaction(transaction);
                    if sent == 0 || received + MASTERNODE_COST + transaction.fee_used() == sent {
                        addresses.push(address);
                    }
                } else {
                    match self.direction_of_transaction(transaction) {
                        TransactionDirection::Sent => {
                            if !self.contains_internal_address(Some(address.clone())) {
                                addresses.push(address);
                            }
                        },
                        TransactionDirection::Received => {
                            if !self.contains_address(Some(address.clone())) {
                                addresses.push(address);
                            }
                        },
                        TransactionDirection::Moved => {
                            if !self.contains_external_address(Some(address.clone())) {
                                addresses.push(address);
                            }
                        },
                        _ => {}
                    }
                }

            } else if self.direction_of_transaction(transaction) == TransactionDirection::Sent {
                if let Some(script) = &output.script {
                    if script[0] == OP_RETURN.into_u8() {
                        let length = script[1];
                        if script[2] == OP_SHAPESHIFT.into_u8() {
                            let mut writer = Vec::<u8>::new();
                            BITCOIN_PUBKEY_ADDRESS.enc(&mut writer);
                            // todo: check bounds are valid
                            writer.emit_slice(&script[3..script.len() - 1])
                                .expect("Error writer script");
                            // todo: ensure [NSString base58checkWithData:data]
                            addresses.push(&base58::check_encode_slice(&writer));
                        }
                    } else {
                        addresses.push(&format!("Unknown address"));
                    }
                }
            }
            addresses
        })
    }


    /// Fees

    /// The fee for the given transaction if all its inputs are from wallet transactions, UINT64_MAX otherwise
    pub fn fee_for_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        let mut amount = 0u64;
        for input in transaction.inputs() {
            let n = input.index as usize;
            if let Some(tx) = self.all_tx.get(&input.input_hash) {
                if n >= tx.outputs().len() {
                    return u64::MAX;
                } else if let Some(output) = tx.outputs().get(n) {
                    amount += output.amount;
                }
            }
        }
        for output in transaction.outputs() {
            amount -= output.amount;
        }
        amount
    }

    /// Outputs

    /// largest amount that can be sent from the account after fees
    pub fn max_output_amount(&self) -> (u64, u32) {
        self.max_output_amount_with_confirmation_count(0)
    }

    // returns (max_output: u64, input_count: u32)
    pub fn max_output_amount_with_confirmation_count(&self, confirmation_count: u64) -> (u64, u32) {
        let mut input_count = 0u32;
        let mut amount = 0u64;
        let mut fee = 0u64;
        let mut cpfp_size: usize = 0;
        let mut tx_size: usize = 0;
        for o in self.utxos {
            if let Some(tx) = self.all_tx.get(&o.hash) {
                let outputs = tx.outputs();
                if o.n >= outputs.len() as u32 ||
                    (confirmation_count != 0 && tx.block_height() >= self.block_height() - confirmation_count) {
                    continue;
                }
                input_count += 1;
                amount += outputs[o.n].amount;
                // size of unconfirmed, non-change inputs for child-pays-for-parent fee
                // don't include parent tx with more than 10 inputs or 10 outputs
                if tx.block_height() == TX_UNCONFIRMED as u32 && tx.inputs().len() < 10 && outputs.len() <= 10 && self.amount_sent_by_transaction(tx) == 0 {
                    cpfp_size += tx.size();
                }
            }
        }
        tx_size = 8 + VarInt(input_count as u64).len() + TX_INPUT_SIZE * input_count + VarInt(2).len() + TX_OUTPUT_SIZE * 2;
        fee = self.wallet.unwrap().chain.fee_for_tx_size(tx_size + cpfp_size);
        if amount > fee {
            (amount - fee, input_count)
        } else {
            (0, input_count)
        }
    }

    /// Private Key Sweeping

    // given a private key, queries dash insight for unspent outputs and calls the completion block with a signed transaction
    // that will sweep the balance into the account (doesn't publish the tx)
    // this can only be done on main chain for now
    pub fn sweep_private_key(&self, priv_key: String, with_fee: bool) -> Result<(&dyn ITransaction, u64), util::Error> {
        todo!()
    }


}
