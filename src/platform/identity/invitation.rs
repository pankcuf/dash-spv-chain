use crate::chain::chain::Chain;
use crate::chain::dispatch_context::DispatchContext;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::UInt256;
use crate::crypto::primitives::utxo::UTXO;
use crate::notifications::{Notification, NotificationCenter};
use crate::platform::identity::identity::Identity;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::account::invitation::InvitationEntity;
use crate::storage::models::entity::Entity;

pub type VerifyInvitationLinkCallback = fn(dyn ITransaction, bool, Error);

pub struct Invitation {
    /// This is the identity that was made from the invitation.
    /// There should always be an identity associated to a blockchain invitation.
    /// This identity might not yet be registered on Dash Platform.
    pub identity: &'static Identity,
    /// This is an invitation that was created locally.
    pub created_locally: bool,
    /// This is an invitation that was created with an external link, and has not yet retrieved the identity.
    pub needs_identity_retrieval: bool,
    /// This is the wallet holding the blockchain invitation. There should always be a wallet associated to a blockchain invitation.
    pub wallet: &'static Wallet,
    /// A name for locally created invitation.
    pub name: Option<String>,
    /// A tag for locally created invitation.
    pub tag: Option<String>,
    pub link: Option<String>,

    pub is_transient: bool,

    pub chain: &'static Chain,
}

/// Deletion
impl Invitation {
    pub(crate) fn delete_persistent_object_and_save(&self, save: bool, context: &ManagedContext) {
        if let Ok(entity) = InvitationEntity::get_by_identity_unique_id(&self.identity.unique_id, context) {
            // TODO: save ???
            InvitationEntity::delete_by_id(entity.id, context).expect("Can't delete invitation");
        }
    }
}

impl Invitation {

    pub fn init_at_index(index: u32, wallet: &Wallet) -> Self {
        let mut identity = Identity::init_at(index, wallet);
        let mut s = Self {
            wallet,
            created_locally: true,
            identity: &identity,
            chain: wallet.chain,
            ..Default::default()
        };
        identity.set_associated_invitation(&s);
        s
    }


    pub fn init_at_with_funding_transaction(index: u32, transaction: &CreditFundingTransaction, wallet: &Wallet) -> Self {
        //this is the creation of a new blockchain identity
        let mut identity = Identity::init_at_with_credit_funding_transaction_and_username_dictionary(index, transaction, None, wallet).unwrap();
        let mut s = Self {
            wallet,
            is_transient: false,
            created_locally: true,
            identity: &identity,
            chain: wallet.chain,
            needs_identity_retrieval: false
        };
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_at_index_with_locked_outpoint(index: u32, locked_outpoint: &UTXO, wallet: &Wallet) -> Self {
        assert_ne!(index, u32::MAX, "index must be found");
        let mut identity = Identity::init_at_with_locked_outpoint(index, locked_outpoint, wallet);
        let mut s = Self {
            wallet,
            is_transient: false,
            created_locally: true,
            chain: wallet.chain,
            needs_identity_retrieval: false,
            identity: &identity,
        };
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_at_index_with_locked_outpoint_and_invitation_entity(index: u32, locked_outpoint: &UTXO, wallet: &Wallet, entity: &InvitationEntity) -> Self {
        let mut identity = Identity::init_at_with_locked_outpoint_and_entity(index, locked_outpoint, wallet, &entity.get_identity());
        let mut s = Self {
            identity: &identity,
            wallet,
            is_transient: false,
            created_locally: true,
            link: entity.link.clone(),
            name: entity.name.clone(),
            tag: entity.tag.clone(),
            chain: wallet.chain,
            needs_identity_retrieval: false,
        };
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_at_index_with_locked_outpoint_and_identity_entity_and_invitation_entity(index: u32, locked_outpoint: UTXO, wallet: &Wallet, identity_entity: &IdentityEntity, invitation_entity: &InvitationEntity) -> Self {
        let mut identity = Identity::init_at_with_locked_outpoint_and_entity(index, &locked_outpoint, wallet, identity_entity);
        let s = Self {
            wallet,
            is_transient: false,
            created_locally: true,
            identity: &identity,
            name: invitation_entity.name.clone(),
            tag: invitation_entity.tag.clone(),
            link: invitation_entity.link.clone(),
            needs_identity_retrieval: false,
            chain: &wallet.chain
        };
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_with_invitation_link(link: String, wallet: &Wallet) -> Self {
        Self {
            link: Some(link),
            wallet,
            chain: wallet.chain,
            needs_identity_retrieval: true,
            created_locally: false
        }
    }



    pub fn register_in_wallet_for_registration_funding_transaction(&self, transaction: CreditFundingTransaction) {
        // assert!(self.identity , "The identity must already exist");
        self.identity.set_invitation_registration_credit_funding_transaction(transaction);
        self.register_in_wallet_for_blockchain_identity_unique_id(&transaction.credit_burn_identity_identifier());

        // we need to also set the address of the funding transaction to being used so future identities past the initial gap limit are found
        transaction.mark_invitation_address_as_used_in_wallet(self.wallet);
    }

    pub fn register_in_wallet_for_blockchain_identity_unique_id(&self, unique_id: &UInt256) {
        self.identity.set_invitation_unique_id(unique_id);
        self.register_in_wallet();
    }


    pub fn is_registered_in_wallet(&self) -> bool {
        self.wallet.contains_blockchain_invitation(self)
    }

    pub fn register_in_wallet(&self) {
        assert!(self.identity.is_outgoing_invitation, "The underlying identity is not from an invitation");
        if !self.identity.is_outgoing_invitation { return; }
        self.wallet.register_blockchain_invitation(self);
        self.identity.save_initial();
        NotificationCenter::post(Notification::InvitationDidUpdate(self.chain, self));
        // dispatch_async(dispatch_get_main_queue(), ^{
        //     [[NSNotificationCenter defaultCenter] postNotificationName:DSBlockchainInvitationDidUpdateNotification object:nil userInfo:@{DSChainManagerNotificationChainKey: self.chain, DSBlockchainInvitationKey: self}];
        // });
    }


    pub fn update_in_wallet(&self) {
        self.save_in_context(/*[NSManagedObjectContext platformContext]*/)
    }

    pub fn unregister_locally(&self) -> bool {
        assert!(self.identity.is_outgoing_invitation, "The underlying identity is not from an invitation");
        if !self.identity.is_outgoing_invitation || self.identity.is_registered {
            // if the invitation has already been used we can not unregister it
            return false;
        }
        self.wallet.unregister_blockchain_invitation(self);
        self.delete_persistent_object_and_save(true/*, [NSManagedObjectContext platformContext] */);
        true
    }

    pub fn verify_invitation_link(&self, completion: Option<VerifyInvitationLinkCallback>/*, completion_queue: dispatch_queue_t*/) {
        Self::verify_invitation_link_with_completion(&self.link.unwrap(), self.wallet.chain, completion/*, completion_queue*/);
    }

    pub fn verify_invitation_link_with_completion(link: &String, chain: &Chain, completion: Option<VerifyInvitationLinkCallback>, /*, completion_queue: dispatch_queue_t*/) {
        let core_service = &chain.dapi_client().core_service;

    }

    + (void)verifyInvitationLink:(NSString *)invitationLink onChain:(DSChain *)chain completion:(void (^_Nullable)(DSTransaction *transaction, bool spent, NSError *error))completion completionQueue:(dispatch_queue_t)completionQueue {
    DSDAPICoreNetworkService *coreNetworkService = chain.chainManager.DAPIClient.DAPICoreNetworkService;
    NSURLComponents *components = [NSURLComponents componentsWithString:invitationLink];
    NSArray *queryItems = components.queryItems;
    UInt256 assetLockTransactionHash = UINT256_ZERO;
    DSECDSAKey *fundingPrivateKey = nil;
    for (NSURLQueryItem *queryItem in queryItems) {
    if ([queryItem.name isEqualToString:@"assetlocktx"]) {
    NSString *assetLockTransactionHashString = queryItem.value;
    assetLockTransactionHash = assetLockTransactionHashString.hexToData.UInt256;
    } else if ([queryItem.name isEqualToString:@"pk"]) {
    NSString *fundingPrivateKeyString = queryItem.value;
    fundingPrivateKey = [DSECDSAKey keyWithPrivateKey:fundingPrivateKeyString onChain:chain];
    }
    }
    if (uint256_is_zero(assetLockTransactionHash)) {
    if (completion) {
    completion(nil, NO, [NSError errorWithCode:400 localizedDescriptionKey:@"Invitation format is not valid"]);
    }
    return;
    }
    if (!fundingPrivateKey || uint256_is_zero(*fundingPrivateKey.secretKey)) {
    if (completion) {
    completion(nil, NO, [NSError errorWithCode:400 localizedDescriptionKey:@"Funding private key is not valid"]);
    }
    return;
    }

    [coreNetworkService getTransactionWithHash:assetLockTransactionHash
    completionQueue:completionQueue
    success:^(DSTransaction *_Nonnull transaction) {
    NSAssert(transaction, @"transaction must not be null");
    if (!transaction || ![transaction isKindOfClass:[DSCreditFundingTransaction class]]) {
    if (completion) {
    completion(nil, NO, [NSError errorWithCode:400 localizedDescriptionKey:@"Invitation transaction is not valid"]);
    }
    return;
    }
    if (completion) {
    completion(transaction, NO, nil);
    }
    }
    failure:^(NSError *_Nonnull error) {
    if (completion) {
    completion(nil, NO, [NSError errorWithCode:400 localizedDescriptionKey:@"Invitation format is not valid"]);
    }
    }];
}

}
