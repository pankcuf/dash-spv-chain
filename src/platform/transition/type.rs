// Special Transaction
// https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md

use crate::platform::base::serializable_object::SerializableValue;
use crate::platform::transition::transition::TransitionKey;

#[derive(Debug)]
pub enum Type {
    DataContract = 0,
    Documents = 1,
    IdentityRegistration = 2,
    IdentityTopUp = 3,
    IdentityUpdateKey = 4,
    IdentityCloseAccount = 5,
}

impl SerializableValue for Type {

}
