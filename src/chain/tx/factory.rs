use byte::BytesExt;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::Transaction;
use crate::chain::chain::Chain;
use crate::chain::tx::transaction_type::TransactionType;

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
            TransactionType::from(bytes.read_with::<u16>(&mut 2, endian).unwrap())
        }
    }

    pub fn transaction_with_message(message: &[u8], chain: &Chain) -> Option<dyn ITransaction> {
        let version = message.read_with::<u16>(&mut 0, byte::LE).unwrap();
        let r#type = if version < 3 {
            TransactionType::Classic
        } else {
            TransactionType::from(bytes.read_with::<u16>(&mut 2, endian).unwrap())
        };

        match r#type {
            TransactionType::Classic => {
                let transaction = Transaction::tr
            }
            case DSTransactionType_Classic: {
                DSTransaction *transaction = [DSTransaction transactionWithMessage:message onChain:chain];


                if ([transaction isCreditFundingTransaction]) {
                //replace with credit funding transaction
                transaction = [DSCreditFundingTransaction transactionWithMessage:message onChain:chain];
                }
                return transaction;
            }
            case DSTransactionType_Coinbase:
            return [DSCoinbaseTransaction transactionWithMessage:message onChain:chain];
            case DSTransactionType_ProviderRegistration:
            return [DSProviderRegistrationTransaction transactionWithMessage:message onChain:chain];
            case DSTransactionType_ProviderUpdateService:
            return [DSProviderUpdateServiceTransaction transactionWithMessage:message onChain:chain];
            case DSTransactionType_ProviderUpdateRegistrar:
            return [DSProviderUpdateRegistrarTransaction transactionWithMessage:message onChain:chain];
            case DSTransactionType_ProviderUpdateRevocation:
            return [DSProviderUpdateRevocationTransaction transactionWithMessage:message onChain:chain];
            case DSTransactionType_QuorumCommitment:
            return [DSQuorumCommitmentTransaction transactionWithMessage:message onChain:chain];
            default:
            return [DSTransaction transactionWithMessage:message onChain:chain]; //we won't be able to check the payload, but try best to support it.
        }


    }



}
