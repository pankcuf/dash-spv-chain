use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use byte::BytesExt;
use hashes::{Hash, sha256, sha256d};
use ring::{hmac, rand};
use crate::chain::chain::Chain;
use crate::chain::options::sync_type::SyncType;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::bip39_mnemonic::{BIP39_CREATION_TIME, BIP39_WALLET_UNKNOWN_CREATION_TIME, BIP39Mnemonic};
use crate::chain::wallet::special_transaction_wallet_holder::SpecialTransactionWalletHolder;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{Reversable, Zeroable};
use crate::crypto::primitives::utxo::UTXO;
use crate::crypto::{UInt160, UInt256};
use crate::{derivation, Environment};
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::wallet::bip39_language::Bip39Language;
use crate::chain::wallet::extension::identities::WalletIdentities;
use crate::chain::wallet::extension::invitations::WalletInvitations;
use crate::chain::wallet::extension::seed::{Seed, SeedRequestBlock};
use crate::crypto::data_ops::short_hex_string_from;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::derivation_path;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::incoming_funds_derivation_path::IncomingFundsDerivationPath;
use crate::derivation::masternode_holdings_derivation_path::MasternodeHoldingsDerivationPath;
use crate::derivation::simple_indexed_derivation_path::ISimpleIndexedDerivationPath;
use crate::environment::Environment;
use crate::keychain::keychain::Keychain;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::manager::authentication_manager::AuthenticationError;
use crate::platform::contract::contract::Contract;
use crate::platform::identity::identity::Identity;
use crate::platform::identity::invitation::Invitation;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::entity::EntityConvertible;
use crate::storage::models::tx::special::credit_funding_transaction::CreditFundingTransactionEntity;
use crate::storage::models::tx::transaction::TransactionEntity;
use crate::util::time::TimeUtil;


pub const WALLET_CREATION_TIME_KEY: &str = "WALLET_CREATION_TIME_KEY";
pub const WALLET_CREATION_GUESS_TIME_KEY: &str = "WALLET_CREATION_GUESS_TIME_KEY";
pub const AUTH_PRIVKEY_KEY: &str = "authprivkey";
pub const WALLET_MNEMONIC_KEY: &str = "WALLET_MNEMONIC_KEY";
pub const WALLET_MASTER_PUBLIC_KEY: &str = "WALLET_MASTER_PUBLIC_KEY";
pub const WALLET_BLOCKCHAIN_USERS_KEY: &str = "WALLET_BLOCKCHAIN_USERS_KEY";
pub const WALLET_BLOCKCHAIN_INVITATIONS_KEY: &str = "WALLET_BLOCKCHAIN_INVITATIONS_KEY";

pub const WALLET_ACCOUNTS_KNOWN_KEY: &str = "WALLET_ACCOUNTS_KNOWN_KEY";

pub const WALLET_MASTERNODE_VOTERS_KEY: &str = "WALLET_MASTERNODE_VOTERS_KEY";
pub const WALLET_MASTERNODE_OWNERS_KEY: &str = "WALLET_MASTERNODE_OWNERS_KEY";
pub const WALLET_MASTERNODE_OPERATORS_KEY: &str = "WALLET_MASTERNODE_OPERATORS_KEY";

pub const VERIFIED_WALLET_CREATION_TIME_KEY: &str = "VERIFIED_WALLET_CREATION_TIME";
pub const REFERENCE_DATE_2001: u64 = 978307200;

pub struct Wallet {
    pub chain: &'static Chain,
    pub accounts: HashMap<u32, Account>,

    pub unique_id_string: String,

    wallet_creation_time: Option<u64>, // NSTimeInterval
    guessed_wallet_creation_time: Option<u64>, // NSTimeInterval
    pub checked_wallet_creation_time: bool,
    pub checked_guessed_wallet_creation_time: bool,
    pub checked_verify_wallet_creation_time: bool,

    pub special_transactions_holder: SpecialTransactionsWalletHolder,

    // @property (nonatomic, copy) NSString *uniqueIDString;

    pub masternode_operator_indexes: HashMap<UInt256, u32>,
    pub masternode_owner_indexes: HashMap<UInt256, u32>,
    pub masternode_voter_indexes: HashMap<UInt256, u32>,
    pub masternode_operator_public_key_locations: HashMap<UInt256, String>,
    pub masternode_owner_private_key_locations: HashMap<UInt256, String>,
    pub masternode_voter_key_locations: HashMap<UInt256, String>,

    pub is_transient: bool,
    pub(crate) identities: HashMap<UInt256, Identity>,
    pub(crate) identities_loaded: bool,
    pub(crate) invitations: HashMap<UTXO, Invitation>,
    pub(crate) invitations_loaded: bool,

    pub(crate) seed_request_block: Option<SeedRequestBlock>,
    pub(crate) default_identity: Option<&'static Identity>,

}

/// Invitations
impl Wallet {
    pub fn unique_id_as_str(&self) -> &str {
        self.unique_id_string.as_str()
    }

    pub(crate) fn contains_blockchain_invitation(&self, invitation: &Invitation) -> bool {
        if let Some(outpoint) = invitation.identity.locked_outpoint {
            self.invitations.get(&outpoint).is_some()
        } else {
            false
        }
    }
}

impl Wallet {

    pub fn standard_wallet_with_seed_phrase(seed_phrase: String, creation_date: u64, chain: &mut Chain, store_seed_phrase: bool, is_transient: bool) -> Option<Self> {
        let account = Account::account_with_account_number(0, chain.standard_derivation_paths_for_account_number(0), chain.chain_context());
        // make sure we can create the wallet first
        match Self::set_seed_phrase(seed_phrase, creation_date, vec![account], store_seed_phrase, chain) {
            Ok(unique_id) => {
                Self::register_specialized_derivation_paths_for_seed_phrase(&seed_phrase, unique_id, chain);
                Some(Self::init_with_unique_id_and_accounts(unique_id, Some(vec![account]), chain, store_seed_phrase, is_transient))
            },
            _ => None
        }
    }


    fn init_with_chain(chain: &Chain) -> Self {
        Self {
            chain,
            ..Default::default()
        }
    }

    fn init_with_unique_id_and_accounts(unique_id: String, accounts: Option<Vec<Account>>, chain: &mut Chain, store_seed_phrase: bool, is_transient: bool) -> Self {
        let mut wallet = Self::init_with_chain(chain);
        wallet.unique_id_string = unique_id;
        wallet.seed_request_block = Some(|authprompt, amount, seed_completion| {
            // this happens when we request the seed
            s.seed_with_prompt(authprompt, amount, seed_completion);
        });

        if store_seed_phrase {
            chain.register_wallet(&wallet);
        }

        if is_transient {
            wallet.is_transient = true;
        }
        if let Some(accounts) = accounts {
            // this must be last, as adding the account queries the wallet unique ID
            wallet.add_accounts(accounts);
        }
        chain.derivation_path_factory.loaded_specialized_derivation_paths_for_wallet(&wallet);

        wallet.special_transactions_holder = SpecialTransactionWalletHolder::init_with_wallet(&wallet, chain.chain_context());

        wallet.identities.clear();
        wallet.invitations.clear();
        wallet.blockchain_identities();
        wallet.blockchain_invitations();
        // blockchain users are loaded
        // add blockchain user derivation paths to account
        wallet
    }

    pub(crate) fn init_with_unique_id(unique_id: String, chain: &mut Chain) -> Self {
        let accounts_known = Wallet::accounts_known_for_unique_id(&unique_id);
        let accounts = Account::standard_accounts_to_account_number(accounts_known, chain, chain.chain_context());
        Self::init_with_unique_id_and_accounts(unique_id.clone(), Some(accounts), chain, false, false)
    }

    pub fn accounts_known_key_for_wallet_unique_id(wallet_unique_id: &String) -> String {
        format!("{}_{}", WALLET_ACCOUNTS_KNOWN_KEY, wallet_unique_id)
    }

    pub fn wallet_blockchain_identities_key(&self) -> String {
        format!("{}_{}", WALLET_BLOCKCHAIN_USERS_KEY, self.unique_id_string)
    }

    pub fn wallet_blockchain_identities_default_index_key(&self) -> String {
        format!("{}_{}_DEFAULT_INDEX", WALLET_BLOCKCHAIN_USERS_KEY, self.unique_id_string)
    }

    pub fn wallet_blockchain_invitations_key(&self) -> String {
        format!("{}_{}", WALLET_BLOCKCHAIN_INVITATIONS_KEY, self.unique_id_string)
    }

    pub fn wallet_masternode_voters_key(&self) -> String {
        format!("{}_{}", WALLET_MASTERNODE_VOTERS_KEY, self.unique_id_string)
    }

    pub fn wallet_masternode_owners_key(&self) -> String {
        format!("{}_{}", WALLET_MASTERNODE_OWNERS_KEY, self.unique_id_string)
    }

    pub fn wallet_masternode_operators_key(&self) -> String {
        format!("{}_{}", WALLET_MASTERNODE_OPERATORS_KEY, self.unique_id_string)
    }

    pub fn accounts_known_for_unique_id(unique_id: &String) -> u32 {
        Keychain::get_int(Wallet::accounts_known_key_for_wallet_unique_id(unique_id)).unwrap_or(0) as u32
    }

    pub fn accounts_known(&self) -> u32 {
        Wallet::accounts_known_for_unique_id(&self.unique_id_string)
    }

    fn register_specialized_derivation_paths_for_seed_phrase(seed_phrase: &String, wallet_unique_id: &String, chain: &Chain) {
        if let Some(seed_phrase) = BIP39Mnemonic::normalize_phrase(seed_phrase) {
            let derived_key_data = BIP39Mnemonic::derive_key_from_phrase(&seed_phrase, None);
            let mut provider_owner_keys_path = AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_chain(chain);
            provider_owner_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
            let mut provider_operator_keys_path = AuthenticationKeysDerivationPath::provider_operator_keys_derivation_path_for_chain(chain);
            provider_operator_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
            let mut provider_voting_keys_path = AuthenticationKeysDerivationPath::provider_voting_keys_derivation_path_for_chain(chain);
            provider_voting_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
            let mut provider_funds_path = MasternodeHoldingsDerivationPath::provider_funds_derivation_path_for_chain(chain);
            provider_funds_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
            if chain.is_evolution_enabled() {
                let mut identity_bls_keys_path = AuthenticationKeysDerivationPath::identity_bls_keys_derivation_path_for_chain(chain);
                identity_bls_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
                let mut identity_ecdsa_keys_path = AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_chain(chain);
                identity_ecdsa_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
                let mut identity_registration_funding_path = CreditFundingDerivationPath::identity_registration_funding_derivation_path_for_chain(chain);
                identity_registration_funding_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
                let mut identity_topup_funding_path = CreditFundingDerivationPath::identity_topup_funding_derivation_path_for_chain(chain);
                identity_topup_funding_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
                let mut identity_invitation_funding_path = CreditFundingDerivationPath::identity_invitation_funding_derivation_path_for_chain(chain);
                identity_invitation_funding_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
            }
        }
    }

    pub fn load_blockchain_identities(&self) {
        // [self.chain.chainManagedObjectContext performBlockAndWait:^{
        self.identities.values().for_each(|identity| {
            match IdentityEntity::aggregate_friendship(&identity.unique_id, context) {
                Ok((incoming, outgoing)) => {
                    incoming.iter().for_each(|request| {
                        if let Some(mut account) = self.account_with_number(request.account_index as u32) {
                            let mut funds_derivation_path = IncomingFundsDerivationPath::contact_based_derivation_path_with_destination_identity_unique_id(request.destination_identity_unique_id, request.source_identity_unique_id, account.account_number, self.chain);
                            funds_derivation_path.base.standalone_extended_public_key_unique_id = Some(request.derivation_path.public_key_identifier.clone());
                            funds_derivation_path.base.wallet = Some(self);
                            funds_derivation_path.base.account = Some(account);
                            account.add_incoming_derivation_path(&mut funds_derivation_path, request.friendship_identifier, self.chain.chain_context());
                        }
                    });
                    outgoing.iter().for_each(|request| {
                        if let Some(mut account) = self.account_with_number(request.account_index as u32) {
                            if let Some(mut funds_derivation_path) = account.derivation_path_for_friendship_with_identifier(&request.friendship_identifier) {
                                // both contacts are on device
                                account.add_outgoing_derivation_path(&mut funds_derivation_path, request.friendship_identifier, self.chain.chain_context());
                            } else {
                                let derivation_path_entity = &request.derivation_path;
                                let mut funds_derivation_path = IncomingFundsDerivationPath::external_derivation_path_with_extended_public_key_unique_id(
                                    &derivation_path_entity.public_key_identifier,
                                    request.destination_identity_unique_id,
                                    request.source_identity_unique_id,
                                    self.chain
                                );
                                funds_derivation_path.base.wallet = Some(self);
                                funds_derivation_path.base.account = Some(account);
                                account.add_outgoing_derivation_path(&mut funds_derivation_path, request.friendship_identifier, self.chain.chain_context());
                            }
                        }
                    });

                },
                Err(err) => println!("Error aggregation friendship: {:?}", err)
            }
        });
        // this adds the extra information to the transaction and must come after loading all blockchain identities.
        self.accounts.values().for_each(|account| {
            account.all_transactions.iter().for_each(|transaction| {
                transaction.load_blockchain_identities_from_derivation_paths(&account.fund_derivation_paths);
                transaction.load_blockchain_identities_from_derivation_paths(&account.outgoing_fund_derivation_paths);
            });
        });
        // }];
    }

    pub fn last_account_number(&self) -> u32 {
        if self.accounts.is_empty() {
            assert!(false, "There should always be at least one account");
            u32::MAX
        } else {
            self.accounts.keys().max()
        }
    }

    pub fn add_account(&mut self, mut account: Account) {
        self.accounts.insert(account.account_number, account);
        account.wallet = Some(self);
        let last_account_number = self.last_account_number();
        if last_account_number > self.accounts_known() {
            Keychain::set_int(
                last_account_number as i64,
                Wallet::accounts_known_key_for_wallet_unique_id(&self.unique_id_string),
                false)
                .expect("Can't save last_account_number in keychain");
        }
    }
    pub fn add_another_account_if_authenticated(&mut self) -> Option<&Account> {
        let add_account_number = self.last_account_number() + 1;
        let derivation_paths = self.chain.standard_derivation_paths_for_account_number(add_account_number);
        let mut add_account = Account::init_with(add_account_number, derivation_paths, self.chain.chain_context());
        if let Some(seed_phrase) = self.seed_phrase_if_authenticated() {
            let derived_key_data = BIP39Mnemonic::derive_key_from_phrase(&seed_phrase, None);
            add_account.fund_derivation_paths.iter().for_each(|mut derivation_path| {
                derivation_path.generate_extended_public_key_from_seed(&derived_key_data, Some(&self.unique_id_string));
            });
            if self.chain.is_evolution_enabled() {
                if let Some(mut master_path) = &add_account.master_contacts_derivation_path {
                    master_path.generate_extended_public_key_from_seed(&derived_key_data, Some(&self.unique_id_string));
                }
            }
            self.add_account(add_account);
            add_account.load_derivation_paths();
            Some(&add_account)
        }
        None
    }

    pub fn add_accounts(&mut self, accounts: Vec<Account>) {
        accounts.iter().for_each(|&account| self.add_account(account))
    }

    pub fn account_with_number(&self, account_number: u32) -> Option<&Account> {
        self.accounts.get(&account_number)
    }

    fn copy_for_chain(&self, mut chain: &mut Chain) -> Result<&Wallet, AuthenticationError> {
        if self.chain == chain {
            return Ok(self);
        }
        let prompt = format!("Please authenticate to create your {:?} wallet", chain.params.chain_type);
        self.seed_phrase_after_authentication_with_prompt(Some(prompt))
            .and_then(|seed_phrase| {
                if let Some(wallet) = Self::standard_wallet_with_seed_phrase(
                    seed_phrase,
                    if self.wallet_creation_time.unwrap() == BIP39_CREATION_TIME { 0 } else { self.wallet_creation_time.unwrap() },
                    chain,
                    true,
                    false) {
                    Ok(&wallet)
                } else {
                    Err(AuthenticationError::CannotCreateWallet)
                }
            })
    }

    /// Unique Identifiers
    pub fn mnemonic_unique_id_for_unique_id(unique_id: &String) -> String {
        format!("{}_{}", WALLET_MNEMONIC_KEY, unique_id)
    }

    pub fn mnemonic_unique_id(&self) -> String {
        Wallet::mnemonic_unique_id_for_unique_id(&self.unique_id_string)
    }

    pub fn creation_time_unique_id_for_unique_id(unique_id: &String) -> String {
        format!("{}_{}", WALLET_CREATION_GUESS_TIME_KEY, unique_id)
    }

    fn creation_guess_time_unique_id_for_unique_id(unique_id: &String) -> String {
        format!("{}_{}", WALLET_CREATION_GUESS_TIME_KEY, unique_id)
    }

    pub(crate) fn did_verify_creation_time_unique_id_for_unique_id(unique_id: &String) -> String {
        format!("{}_{}", VERIFIED_WALLET_CREATION_TIME_KEY, unique_id)
    }

    pub fn creation_time_unique_id(&self) -> String {
        Self::creation_time_unique_id_for_unique_id(self.unique_id_string())
    }

    pub fn creation_guess_time_unique_id(&self) -> String {
        Self::creation_guess_time_unique_id_for_unique_id(self.unique_id_string())
    }

    pub fn did_verify_creation_time_unique_id(&self) -> String {
        Self::did_verify_creation_time_unique_id_for_unique_id(self.unique_id_string())
    }

    /// Wallet Creation Time

    pub fn wallet_creation_time(&mut self) -> u64 {
        self.verify_wallet_creation_time();
        if let Some(time) = self.wallet_creation_time {
            return time;
        }
        if !self.checked_wallet_creation_time {
            match Keychain::get_data(self.creation_time_unique_id()) {
                Ok(data) => {
                    if data.len() == std::mem::size_of::<u64>() {
                        let potential_wallet_creation_time = data.read_with::<u64>(&mut 0, byte::LE).unwrap();
                        if potential_wallet_creation_time > BIP39_CREATION_TIME as u64 {
                            self.wallet_creation_time = Some(potential_wallet_creation_time);
                            return potential_wallet_creation_time;
                        }
                    }
                    self.checked_wallet_creation_time = true;
                },
                Err(err) => {

                }
            }
        }
        if Environment::watch_only() {
            BIP39_WALLET_UNKNOWN_CREATION_TIME
        } else if let Some(time) = self.guessed_wallet_creation_time() {
            time
        } else {
            BIP39_CREATION_TIME
        }
    }

    pub fn wipe_wallet_info(&mut self) {
        self.wallet_creation_time = None;
        let _ = Keychain::set_data(self.creation_time_unique_id(), None, false);
        let _ = Keychain::set_data(self.creation_guess_time_unique_id(), None, false);
        let _ = Keychain::set_data(self.did_verify_creation_time_unique_id(), None, false);
    }

    pub fn guessed_wallet_creation_time(&mut self) -> u64 {
        if let Some(time) = self.guessed_wallet_creation_time {
            return time;
        }
        if !self.checked_guessed_wallet_creation_time {
            if let Ok(d) = Keychain::get_data(self.creation_guess_time_unique_id) {
                let size = std::mem::size_of::<u64>();
                if d.len() == size {
                    let time = u64::from_le_bytes(d.as_bytes() as [u8; 8]);
                    self.guessed_wallet_creation_time = Some(time);
                    return time;
                }
            }
            self.checked_guessed_wallet_creation_time = true;
        }
        BIP39_WALLET_UNKNOWN_CREATION_TIME
    }

    pub fn set_guessed_wallet_creation_time(&mut self, time: u64) {
        if self.wallet_creation_time.is_none() {
            return;
        }
        if self.guessed_wallet_creation_time() > 0 {
            return;
        }

        if let Ok(saved) = Keychain::set_data(self.creation_guess_time_unique_id(), Some(time.to_le_bytes().to_vec()), false) {
            assert!(saved, "error setting wallet guessed creation time");
        } else {
            assert!(false, "error setting wallet guessed creation time");
        }
        self.guessed_wallet_creation_time = Some(time);
    }

    fn migrate_wallet_creation_time(&mut self) {
        if let Ok(data) = Keychain::get_data(self.creation_time_unique_id) {
            if let Ok(potential_wallet_creation_time) = data.read_with::<u64>(&mut 0, byte::LE) {
                if potential_wallet_creation_time < BIP39_CREATION_TIME as u64 {
                    // it was from reference date for sure
                    // todo: check correct date
                    // NSDate *realWalletCreationDate = [NSDate dateWithTimeIntervalSinceReferenceDate:potentialWalletCreationTime];
                    // NSTimeInterval realWalletCreationTime = [realWalletCreationDate timeIntervalSince1970];

                    // let n = (potential_wallet_creation_time * 1_000_000_000) as u32;
                    // let t = potential_wallet_creation_time.checked_add(REFERENCE_DATE_2001)?;
                    // NaiveDateTime::from_timestamp_opt(t, n)


                    let real_wallet_creation_time = SystemTime::seconds_since_1970() - REFERENCE_DATE_2001 + potential_wallet_creation_time;
                    if real_wallet_creation_time != 0 && real_wallet_creation_time != REFERENCE_DATE_2001 {
                        self.wallet_creation_time = Some(max(real_wallet_creation_time, BIP39_CREATION_TIME as u64)); //safeguard
                        Keychain::set_data(self.creatiom_time_unique_id(), Some(real_wallet_creation_time.to_le_bytes().to_vec()), false).expect("Can't save wallet creation time");
                    } else if real_wallet_creation_time == REFERENCE_DATE_2001 {
                        Keychain::set_data(self.creatiom_time_unique_id(), Some(Vec::from([0u8])), false).expect("Can't save wallet creation time");
                    }
                }
            }
        }
    }

    pub fn verify_wallet_creation_time(&mut self) {
        if !self.checked_wallet_creation_time {
            match Keychain::has_data(self.didVerifyCreationTimeUniqueID) {
                Ok(didVerifyAlready) => {
                    if !didVerifyAlready {
                        self.migrate_wallet_creation_time();
                        match Keychain::set_int(1, self.didVerifyCreationTimeUniqueID, false) {
                            Ok(saved) => {},
                            Err(err) => {
                                println!("wallet.verify_wallet_creation_time: set_int: error: {:?}", err);
                            }
                        }
                    }
                    self.checked_verify_wallet_creation_time = true;
                },
                Err(err) => {
                    println!("wallet.verify_wallet_creation_time: has_data: error: {:?}", err);
                }
            }
        }
    }

    /// Chain Synchronization Fingerprint
    pub fn chain_synchronization_fingerprint(&self) -> Vec<u8> {
        // todo: check validity
        let mut block_height_zones: Vec<u32> = self.all_transactions().iter().map(|tx| tx.block_height() / 500).collect();
        block_height_zones.sort();
        Self::chain_synchronization_fingerprint_for_block_zones(block_height_zones, self.chain.last_sync_block_height)
    }

    pub fn block_zones_from_chain_synchronization_fingerprint(chain_synchronization_fingerprint: Vec<u8>, mut version: u8, mut chain_height: u32) -> HashSet<u16> {
        version = chain_synchronization_fingerprint[0];
        chain_height = (u16::from_be_bytes(chain_synchronization_fingerprint[1..3] as [u8; 2]) as u32) * 500;
        let first_block_zone = u16::from_be_bytes(chain_synchronization_fingerprint[3..5] as [u8; 2]);
        let mut block_zones = HashSet::from([first_block_zone]);
        let mut last_known_block_zone = first_block_zone;
        let mut offset = 0u16;
        (5..chain_synchronization_fingerprint.len()).for_each(|i| {
            let current_data = u16::from_be_bytes(chain_synchronization_fingerprint[i..i+2] as [u8; 2]);
            if current_data & (1 << 15) != 0 {
                // We are in a continuation
                if offset > 0 {
                    offset = -15 + offset;
                }
                (1..16).for_each(|i| {
                    if current_data & (1 << (15 - i)) != 0 {
                        last_known_block_zone = last_known_block_zone - offset + i;
                        offset = i;
                        block_zones.push(last_known_block_zone);
                    }
                });
            } else {
                // this is a new zone
                offset = 0;
                last_known_block_zone = currentData;
                block_zones.push(last_known_block_zone);
            }
        });
        block_zones
    }

    pub fn chain_synchronization_fingerprint_for_block_zones(block_height_zones: Vec<u32>, chain_height: u32) -> Vec<u8> {
        return if let Some(first_zone) = block_height_zones.first() {
            let mut fingerprint_data = Vec::<u8>::new();
            1u8.enc(&mut fingerprint_data); // version 1
            ((chain_height / 500) as u16).to_be_bytes().enc(&mut fingerprint_data); // last sync block height
            let mut previous_block_height_zone = first_zone as u16;
            previous_block_height_zone.to_be_bytes().enc(&mut fingerprint_data); // first one
            let mut current_offset = 0u8;
            let mut current_continuation_data = 0u16;
            block_height_zones.iter().skip(1).for_each(|block_zone_number| {
                let current_block_height_zone = block_zone_number as u16;
                let distance = current_block_height_zone - previous_block_height_zone;
                if (current_offset == 0 && distance >= 15) || distance >= (30 - current_offset) as u16 {
                    if current_continuation_data != 0 {
                        current_continuation_data.enc(&mut fingerprint_data);
                        current_offset = 0;
                        current_continuation_data = 0;
                    }
                    current_block_height_zone.to_be_bytes().enc(&mut fingerprint_data);
                } else {
                    current_offset += distance;
                    if current_offset > 15 {
                        current_offset %= 15;
                        current_continuation_data.to_be_bytes().enc(&mut fingerprint_data);
                        current_continuation_data = 1 << 15;
                    }
                    if current_continuation_data == 0 {
                        current_continuation_data = 1 << 15; // start with a 1 to show current continuation data
                    }
                    let current_offset_bit = 1 << (15 - current_offset);
                    current_continuation_data |= current_offset_bit;
                }
                previous_block_height_zone = current_block_height_zone;
            });
            if current_continuation_data != 0 {
                current_continuation_data.to_be_bytes().enc(&mut fingerprint_data);
            }
            fingerprintData
        } else {
            vec![]
        }
    }



    /// Authentication

    /// private key for signing authenticated api calls
/* No need to use
  pub fn auth_private_key(&self, completion: fn(String)) {
        let prompt = format!("Please authorize");
        (self.seed_request_block.unwrap())(Some(prompt), 0, |seed, cancelled| {
            if let Ok(priv_key) = Keychain::get_string(AUTH_PRIVKEY_KEY.to_string()) {
                completion(priv_key);
            } else {
                let priv_key = ECDSAKey::serialized_auth_private_key_from_seed(seed, self.chain);
                Keychain::set_string(priv_key, AUTH_PRIVKEY_KEY.to_string(), false).expect("Can't store auth private key");
                completion(priv_key);
            }
        });
    }
*/
    /// Combining Accounts

    pub fn balance(&self) -> u64 {
        self.accounts
            .iter()
            .map(|account| account.balance)
            .sum()
    }

    pub fn register_addresses_with_gap_limit(&self, gap_limit: u32, unused_account_gap_limit: u32, dashpay_gap_limit: u32, internal: bool) -> Vec<dyn IDerivationPath> {
        self.accounts.values().fold(Vec::new(), |mut arr, account| {
            match account.register_addresses_with_gap_limit(gap_limit, unused_account_gap_limit, dashpay_gap_limit, internal) {
                Ok(data) => {
                    arr.extend(data);
                    arr
                },
                Err(err) => {}
            }
        })
    }

    pub fn first_account_that_can_contain_transaction(&self, transaction: &dyn ITransaction) -> Option<&Account> {
        self.accounts.values().find(|account| account.can_contain_transaction(transaction))
    }

    pub fn accounts_that_can_contain_transaction(&self, transaction: &dyn ITransaction) -> Vec<&Account> {
        self.accounts.values().fold(Vec::new(), |mut accounts, account| {
            if account.can_contain_transaction(transaction) {
                accounts.push(account);
            }
            accounts
        })
    }

    /// all previously generated external addresses
    pub fn all_receive_addresses(&self) -> HashSet<String> {
        self.accounts.values().fold(HashSet::new(), |mut arr, account| {
            arr.extend(account.external_addresses());
            arr
        })
    }

    /// all previously generated internal addresses
    pub fn all_change_addresses(&self) -> HashSet<String> {
        self.accounts.values().fold(HashSet::new(), |mut arr, account| {
            arr.extend(account.internal_addresses());
            arr
        })
    }

    pub fn all_transactions(&self) -> HashSet<dyn ITransaction> {
        self.accounts.values().fold(HashSet::new(), |mut arr, account| {
            arr.extend(account.all_transactions.clone());
            arr
        })
    }

    pub fn all_transactions_for_account(&self, account: &Account) -> HashSet<dyn ITransaction> {
        let mut set = HashSet::new();
        set.extend(account.all_transactions.clone());
        set.extend(self.special_transactions_holder.all_transactions().clone());
        set
    }

    pub fn transaction_for_hash(&self, tx_hash: &UInt256) -> Option<dyn ITransaction> {
        if let Some(tx) = self.accounts.values().filter_map(|account| account.transaction_for_hash(tx_hash)) {
            Some(tx)
        } else if let Some(tx) = self.special_transactions_holder.transaction_for_hash(tx_hash) {
            Some(tx)
        } else {
            None
        }
    }

    pub fn unspent_outputs(&self) -> HashSet<UTXO> {
        self.accounts.values().fold(HashSet::new(), |mut arr, account| {
            arr.extend(account.unspent_outputs.clone());
            arr
        })
    }

    /// true if the address is controlled by the wallet, this can also be for paths that are not accounts (todo)
    pub fn contains_address(&self, address: Option<String>) -> bool {
        self.accounts.values().filter(|account| account.contains_address(address)).count() > 0
    }

    /// true if the address is controlled by the wallet, this can also be for paths that are not accounts (todo)
    pub fn accounts_base_derivation_paths_contain_address(&self, address: Option<String>) -> bool {
        self.accounts.values().filter(|account| account.base_derivation_paths_contain_address(address)).count() > 0
    }

    /// returns the first account with a balance
    pub fn first_account_with_balance(&self) -> Option<&Account> {
        self.accounts
            .values()
            .find(|&acc| acc.balance > 0)
    }

    pub fn account_for_address(&self, address: Option<String>) -> Option<&Account> {
        self.accounts.values().find(|account| account.contains_address(address))
    }

    pub fn account_for_dashpay_external_derivation_path_address(&self, address: Option<String>) -> Option<&Account> {
        self.accounts.values().find(|account| account.external_derivation_path_containing_address(address).is_some())
    }

    /// true if the address was previously used as an input or output in any wallet transaction
    pub fn address_is_used(&self, address: Option<String>) -> bool {
        self.accounts.values().find(|account| account.address_is_used(address)).is_some()
    }

    pub fn transaction_address_already_seen_in_outputs(&self, address: Option<String>) -> bool {
        self.accounts.values().find(|account| account.transaction_address_already_seen_in_outputs(address)).is_some()
    }

    /// returns the amount received by the wallet from the transaction (total outputs to change and/or receive addresses)
    pub fn amount_received_from_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        self.accounts.values().map(|account| account.amount_received_from_transaction(transaction)).sum()
    }

    /// retuns the amount sent from the wallet by the trasaction (total wallet outputs consumed, change and fee included)
    pub fn amount_sent_by_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        self.accounts.values().map(|account| account.amount_sent_by_transaction(transaction)).sum()
    }

    // set the block heights and timestamps for the given transactions, use a height of TX_UNCONFIRMED and timestamp of 0 to
    // indicate a transaction and it's dependents should remain marked as unverified (not 0-conf safe)
    pub fn set_block_height(&mut self, height: u32, timestamp: u64, transaction_hashes: &Vec<UInt256>) -> Vec<UInt256> {
        if transaction_hashes.is_empty() {
            return vec![];
        }
        let mut updated = Vec::<UInt256>::new();
        self.accounts.values_mut().for_each(|mut account| {
            if let Some(from_account) = account.set_block_height(height, timestamp, transaction_hashes) {
                updated.push(from_account);
            } else {
                self.chain_updated_block_height(height);
            }
        });
        self.special_transactions_holder.set_block_height(height, timestamp, transaction_hashes);
        updated
    }

    /// this is used to save transactions atomically with the block, needs to be called before switching threads to save the block
    pub fn prepare_for_incoming_transaction_persistence_for_block_save_with_number(&mut self, block_number: u32) {
        self.accounts.values_mut().for_each(|mut account| account.prepare_for_incoming_transaction_persistence_for_block_save_with_number(block_number));
        self.special_transactions_holder.prepare_for_incoming_transaction_persistence_for_block_save_with_number(block_number);
    }

    /// this is used to save transactions atomically with the block
    pub fn persist_incoming_transactions_attributes_for_block_save_with_number(&mut self, block_number: u32, context: &ManagedContext) {
        self.accounts.values_mut().for_each(|mut account| account.persist_incoming_transactions_attributes_for_block_save_with_number(block_number, context));
        self.special_transactions_holder.persist_incoming_transactions_attributes_for_block_save_with_number(block_number, context);
    }

    pub fn chain_updated_block_height(&mut self, height: u32) {
        self.accounts.values_mut().for_each(|mut account| account.chain_updated_block_height(height))
    }

    pub fn account_for_transaction_hash(&self, tx_hash: &UInt256) -> Option<(&Account, &dyn ITransaction)> {
        self.accounts.values().find_map(|account| {
            if let Some(tx) = account.transaction_for_hash(tx_hash) {
                Some((&account, &tx))
            } else {
                None
            }
        })
    }

    pub fn transaction_is_valid(&self, transaction: &dyn ITransaction) -> bool {
        self.accounts.values().filter(|account| !account.transaction_is_valid(transaction)).count() > 0
    }

    pub fn private_key_for_address(&self, address: Option<String>, seed: &Vec<u8>) -> Option<&dyn IKey> {
        self.account_for_address(address)
            .and_then(|account| account.derivation_path_containing_address(address.clone())
                .and_then(|path| path.index_path_for_known_address(address.clone())
                    .and_then(|index_path| derivation_path.private_key_at_index_path(&index_path, seed))))
    }

    pub fn reload_derivation_paths(&self) {
        self.accounts.values().for_each(|account| account.fund_derivation_paths.iter().for_each(|mut path| path.reload_addresses()));
        self.specialized_derivation_paths().iter_mut().for_each(|mut path| path.reload_addresses());
    }

    pub fn specialized_derivation_paths(&self) -> Vec<dyn IDerivationPath> {
        self.chain.derivation_path_factory.loaded_specialized_derivation_paths_for_wallet(self)
    }

    pub fn has_an_extended_public_key_missing(&self) -> bool {
        //todo add non funds derivation paths
        self.accounts.values().find(|account| account.has_an_extended_public_key_missing).is_some()
    }


    /// Wiping

    pub fn wipe_blockchain_info(&mut self, context: &ManagedContext) {
        self.accounts.values_mut().for_each(|account| account.wipe_blockchain_info());
        self.special_transactions_holder.remove_all_transactions();
        self.wipe_blockchain_identities(context);
        self.wipe_blockchain_invitations(context);
    }

    pub fn wipe_blockchain_extra_accounts(&mut self, context: &ManagedContext) {
        let mut all_account_keys: Vec<_> = self.accounts.into_keys().collect();
        all_account_keys.remove(0);
        if all_account_keys.contains(&1) && &self.chain.options.sync_type & SyncType::MultiAccountAutoDiscovery != 0 {
            // In this case we want to keep account 1
            all_account_keys.remove(1);
        }
        if !all_account_keys.is_empty() {
            all_account_keys.iter().for_each(|key| {
                self.accounts.remove_entry(key);
            });
        }
    }

    pub fn wipe_blockchain_identities_in_context(&mut self, context: &ManagedContext) {
        self.identities.values().for_each(|identity| {
            self.unregister_blockchain_identity(identity);
            identity.delete_persistent_object_and_save(false, context);
        });
        self.default_identity = None;
    }




    pub fn last_sync_block_height(&mut self) -> u32 {
        self.chain.last_sync_block_height()
    }
}
