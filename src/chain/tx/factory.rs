use byte::BytesExt;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::{CoinbaseTransaction, Transaction};
use crate::chain::chain::Chain;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::tx::provider_registration_transaction::ProviderRegistrationTransaction;
use crate::chain::tx::provider_update_registrar_transaction::ProviderUpdateRegistrarTransaction;
use crate::chain::tx::provider_update_revocation_transaction::ProviderUpdateRevocationTransaction;
use crate::chain::tx::provider_update_service_transaction::ProviderUpdateServiceTransaction;
use crate::chain::tx::quorum_commitment_transaction::QuorumCommitmentTransaction;
use crate::chain::tx::transaction_type::TransactionType;

#[derive(Debug, Default)]
pub struct Factory {

}

impl Factory {

    pub fn ignore_messages_of_transaction_type(r#type: TransactionType) -> bool {
        match r#type {
            TransactionType::Classic |
            TransactionType::Coinbase |
            TransactionType::SubscriptionRegistration |
            TransactionType::SubscriptionTopUp |
            TransactionType::SubscriptionCloseAccount |
            TransactionType::SubscriptionResetKey |
            TransactionType::ProviderRegistration |
            TransactionType::ProviderUpdateService |
            TransactionType::ProviderUpdateRegistrar |
            TransactionType::ProviderUpdateRevocation => false,
            TransactionType::QuorumCommitment | _ => true
        }
    }

    pub fn should_ignore_transaction_message(message: &[u8]) -> bool {
        Self::ignore_messages_of_transaction_type(Self::transaction_type_of_message(message))
    }


    pub fn transaction_type_of_message(message: &[u8]) -> TransactionType {
        let version = message.read_with::<u16>(&mut 0, byte::LE).unwrap();
        if version < 3 {
            TransactionType::Classic
        } else {
            TransactionType::from(message.read_with::<u16>(&mut 2, byte::LE).unwrap())
        }
    }

    pub fn transaction_with_message(message: &[u8], chain: &Chain) -> Option<Box<dyn ITransaction>> {
        let version = message.read_with::<u16>(&mut 0, byte::LE).unwrap();
        let r#type = if version < 3 {
            TransactionType::Classic
        } else {
            TransactionType::from(message.read_with::<u16>(&mut 2, byte::LE).unwrap())
        };
        match r#type {
            TransactionType::Classic => match message.read_with::<Transaction>(&mut 0, chain) {
                Ok(tx) if tx.is_credit_funding_transaction() => message.read_with::<CreditFundingTransaction>(&mut 0, chain).ok().map(Box::new),
                Ok(tx) => Box::new(Some(tx)),
                _ => Box::new(None)
            },
            TransactionType::Coinbase => message.read_with::<CoinbaseTransaction>(&mut 0, chain).ok().map(Box::new),
            TransactionType::ProviderRegistration => message.read_with::<ProviderRegistrationTransaction>(&mut 0, chain).ok().map(Box::new),
            TransactionType::ProviderUpdateService => message.read_with::<ProviderUpdateServiceTransaction>(&mut 0, chain).ok().map(Box::new),
            TransactionType::ProviderUpdateRegistrar => message.read_with::<ProviderUpdateRegistrarTransaction>(&mut 0, chain).ok().map(Box::new),
            TransactionType::ProviderUpdateRevocation => message.read_with::<ProviderUpdateRevocationTransaction>(&mut 0, chain).ok().map(Box::new),
            TransactionType::QuorumCommitment => message.read_with::<QuorumCommitmentTransaction>(&mut 0, chain).ok().map(Box::new),
            // we won't be able to check the payload, but try best to support it.
            _ => message.read_with::<Transaction>(&mut 0, chain).ok().map(Box::new)
        }
    }

}
