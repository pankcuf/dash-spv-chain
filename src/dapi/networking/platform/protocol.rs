use std::time::SystemTime;
use crate::chain::dispatch_context::DispatchContext;
use crate::crypto::UInt256;
use crate::dapi::networking::platform::dto::address_summary::AddressSummary;
use crate::dapi::networking::platform::dto::block_header::BlockHeader;
use crate::dapi::networking::platform::dto::block_info::BlockInfo;
use crate::dapi::networking::platform::dto::historic_chain_status::HistoricChainStatus;
use crate::dapi::networking::platform::dto::identity::IdentityDTO;
use crate::dapi::networking::platform::dto::transaction_info::TransactionInfo;
use crate::chain::network::bloom_filter::BloomFilter;
use crate::dapi::networking::platform::dto::contract_info::ContractInfo;
use crate::dapi::networking::platform::dto::masternode_list_info::MasternodeListInfo;
use crate::dapi::networking::platform::dto::transition_info::TransitionInfo;
use crate::platform::transition::transition::ITransition;
use crate::util;

pub trait Protocol {


    ///
    /// # Estimates the transaction fee necessary for confirmation to occur within a certain number of blocks (duffs per kilobyte)
    ///
    /// # Arguments:
    /// * `number_of_blocks_to_wait`: Number of blocks for fee estimate
    ///
    /// # Returns:
    /// * Result<u64, Error>
    /// ```
    fn estimate_fee_with_number_of_blocks_to_wait(&self, number_of_blocks_to_wait: u32) -> Result<u64, util::Error>;

    ///
    /// # Get an address summary given an addresses
    ///
    /// # Arguments:
    /// * `addresses`: Dash addresses
    /// * `no_tx_list`: true if a list of all txs should NOT be included in result
    /// * `from`: start of range for the tx to be included in the tx list
    /// * `to`: end of range for the tx to be included in the tx list
    /// * `from_height`: which height to start from (optional, overriding from/to)
    /// * `to_height`: on which height to end (optional, overriding from/to)
    ///
    /// # Returns:
    /// * Result<AddressSummary, Error>
    /// ```
    fn get_address_summary(&self, addresses: Vec<String>, no_tx_list: bool, from: u64, to: u64, from_height: u32, to_height: u32) -> Result<AddressSummary, util::Error>;


    ///
    /// # Get the total amount of duffs received by an addresses
    ///
    /// # Arguments
    /// * `addresses`: Dash addresses
    /// * `no_tx_list`: true if a list of all txs should NOT be included in result
    /// * `from`: start of range for the tx to be included in the tx list
    /// * `to`: end of range for the tx to be included in the tx list
    /// * `from_height`: which height to start from (optional, overriding from/to)
    /// * `to_height`: on which height to end (optional, overriding from/to)
    ///
    /// # Returns:
    /// * Result<u64, Error>
    ///
    /// ```
    fn get_address_total_received(&self, addresses: Vec<String>) -> Result<u64, util::Error>;

    ///
    /// # Get the total amount of duffs sent by an addresses
    ///
    /// # Arguments
    /// * `addresses`: Dash addresses
    ///
    /// # Returns:
    /// * Result<u64, Error>
    ///
    /// ```
    fn get_address_total_sent(&self, addresses: Vec<String>) -> Result<u64, util::Error>;

    ///
    /// # Get the total unconfirmed balance for the addresses
    ///
    /// # Arguments
    /// * `addresses`: Dash addresses
    ///
    /// # Returns:
    /// * Result<u64, Error>
    ///
    /// ```
    fn get_address_unconfirmed_balance(&self, addresses: Vec<String>) -> Result<u64, util::Error>;

    ///
    /// # Get the calculated balance for the addresses
    ///
    /// # Arguments
    /// * `addresses`: Dash addresses
    ///
    /// # Returns:
    /// * Result<u64, Error>
    ///
    /// ```
    fn get_balance_for_address(&self, addresses: Vec<String>) -> Result<u64, util::Error>;

    ///
    /// # Get block hash of chain tip
    ///
    /// # Returns:
    /// * Result<UInt256, Error>
    ///
    /// ```
    fn get_best_block_hash_success(&self) -> Result<UInt256, util::Error>;

    ///
    /// # Get the best block height
    ///
    /// # Returns:
    /// * Result<u32, Error>
    ///
    /// ```
    fn get_best_block_height_success(&self) -> Result<u32, util::Error>;

    ///
    /// # Get the block hash for the given height
    ///
    /// # Arguments
    /// * `height`: Block height
    ///
    /// # Returns:
    /// * Result<UInt256, Error>
    ///
    /// ```
    fn get_block_hash_for_height(&self, height: u32) -> Result<UInt256, util::Error>;

    ///
    /// # Get the block header corresponding to the requested block hash
    ///
    /// # Arguments
    /// * `block_hash`: Block hash
    ///
    /// # Returns:
    /// * Result<Vec<BlockHeader>, Error>
    ///
    /// ```
    fn get_block_header_for_hash(&self, block_hash: UInt256) -> Result<Vec<BlockHeader>, util::Error>;

    ///
    /// # Get the requested number of block headers starting at the requested height
    ///
    /// # Arguments
    /// * `offset`: Lowest block height to include
    /// * `limit`: The number of headers to return (0 < limit <=25)
    ///
    /// # Returns:
    /// * Result<Vec<BlockHeader>, Error>
    ///
    /// ```
    fn get_block_headers_from_offset(&self, offset: u32, limit: u32) -> Result<Vec<BlockHeader>, util::Error>;

    ///
    /// # Get info for blocks meeting the provided criteria
    ///
    /// # Arguments
    /// * `date`: Starting date for blocks to get
    ///
    /// # Returns:
    /// * Result<Vec<BlockHeader>, Error>
    ///
    /// ```
    fn get_blocks_starting_date(&self, date: SystemTime, limit: u32) -> Result<Vec<BlockHeader>, util::Error>;

    ///
    /// # Get historic blockchain data sync status
    ///
    /// # Returns:
    /// * Result<HistoricChainStatus, Error>
    ///
    /// ```
    fn get_historic_blockchain_data_sync_status(&self) -> Result<HistoricChainStatus, util::Error>;

    ///
    /// # Get mempool usage info
    ///
    /// # Returns:
    /// * Result<u32, Error>
    ///
    /// ```
    fn get_mempool_info(&self) -> Result<u32, util::Error>;

    ///
    /// # Get masternode list
    ///
    /// # Returns:
    /// * Result<MasternodeListInfo, Error>
    ///
    /// ```
    fn get_masternode_list(&self) -> Result<MasternodeListInfo, util::Error>;

    ///
    /// # Get masternode list diff for the provided block hashes
    ///
    /// # Arguments
    /// * `base_block_hash`: Block hash
    /// * `block_hash`: Block hash
    ///
    /// # Returns:
    /// * Result<MasternodeListInfo, Error>
    ///
    /// ```
    fn get_masternode_list_diff(&self, base_block_hash: UInt256, block_hash: UInt256) -> Result<MasternodeListInfo, util::Error>;

    ///
    /// # Get the raw block for the provided block hash
    ///
    /// # Arguments
    /// * `block_hash`: Block hash
    ///
    /// # Returns:
    /// * Result<BlockInfo, Error>
    ///
    /// ```
    fn get_raw_block(&self, block_hash: UInt256) -> Result<BlockInfo, util::Error>;

    ///
    /// # Get block headers
    ///
    /// # Arguments
    /// * `filter`: Bloom filter
    ///
    /// # Returns:
    /// * Result<Vec<BlockHeader>, Error>
    ///
    /// ```
    fn get_spv_data_for_filter(&self, filter: BloomFilter) -> Result<Vec<BlockHeader>, util::Error>;

    ///
    /// # Get transaction for the given hash
    ///
    /// # Arguments
    /// * `tx_id`: The TXID of the transaction
    ///
    /// # Returns:
    /// * Result<TransactionInfo, Error>
    ///
    /// ```
    fn get_transaction_by_id(&self, tx_id: UInt256) -> Result<TransactionInfo, util::Error>;

    ///
    /// # Get transactions for a given address or multiple addresses
    ///
    /// # Arguments
    /// * `addresses`: Dash addresses
    /// * `from`: start of range for the tx to be included in the tx list
    /// * `to`: end of range for the tx to be included in the tx list
    /// * `from_height`: which height to start from (optional, overriding from/to)
    /// * `to_height`: on which height to end (optional, overriding from/to)
    ///
    /// # Returns:
    /// * Result<Vec<TransactionInfo>, Error>
    ///
    /// ```
    fn get_transactions(&self, addresses: Vec<String>, from: u32, to: u32, from_height: Option<u32>, to_height: Option<u32>) -> Result<Vec<TransactionInfo>, util::Error>;

    ///
    /// # Get UTXO for a given address or multiple addresses (max result 1000)
    ///
    /// # Arguments
    /// * `tx_id`: The TXID of the transaction
    ///
    /// # Returns:
    /// * Result<TransactionInfo, Error>
    ///
    /// ```
    fn get_utxo(&self, addresses: Vec<String>) -> Result<TransactionInfo, util::Error>;







    /// Really used:
    ///

    ///
    /// # Fetch a user's Contract
    ///
    /// # Arguments
    /// * `contract_id`: A user's Contract ID
    ///
    /// # Returns:
    /// * Result<IdentityDTO, Error>
    ///
    /// ```
    fn fetch_contract_by_id(&self, contract_id: UInt256/*, completion_queue: dispatch_queue_t*/) -> Result<ContractInfo, util::Error>;

    ///
    /// # Get a blockchain user by username
    ///
    /// # Arguments
    /// * `username`: Blockchain user's username
    /// * `domain`: The domain
    ///
    /// # Returns:
    /// * Result<IdentityDTO, Error>
    ///
    /// ```
    fn get_identity_by_name(&self, username: String, domain: String/*, completion_queue: dispatch_queue_t*/) -> Result<IdentityDTO, util::Error>;

    ///
    /// # Blockchain user's ID
    ///
    /// # Arguments
    /// * `user_id`: Blockchain user's username
    ///
    /// # Returns:
    /// * Result<IdentityDTO, Error>
    ///
    /// ```
    fn get_identity_by_id(&self, user_id: String/*, completion_queue: dispatch_queue_t*/) -> Result<IdentityDTO, util::Error>;

    ///
    /// # Sends raw state transition to the network
    ///
    /// # Arguments
    /// * `state_transition`: Hex-string representing state transition header
    ///
    /// # Returns:
    /// * Result<(IdentityDTO, bool), Error>
    ///
    /// ```
    fn publish_transition(&self, state_transition: &dyn ITransition, dispatch_context: &DispatchContext) -> Result<(TransitionInfo, bool), util::Error>;





}
