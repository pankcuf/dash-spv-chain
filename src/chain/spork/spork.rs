use byte::ctx::Bytes;
use byte::{BytesExt, LE};
use diesel::{ExpressionMethods, Insertable, Table};
use hashes::hex::{FromHex, ToHex};
use crate::chain::chain::Chain;
use crate::chain::constants::DASH_MESSAGE_MAGIC;
use crate::chain::ext::settings::Settings;
use crate::chain::spork::Identifier;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::UInt256;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::schema::sporks;
use crate::storage::models::chain::spork::{NewSporkEntity, SporkEntity};
use crate::storage::models::entity::EntityUpdates;
use crate::util::address::Address;

#[derive(Debug, Default)]
pub struct Spork {
    pub identifier: Identifier,
    pub is_valid: bool,
    pub time_signed: u64,
    pub value: u64,
    pub signature: Vec<u8>,
    pub chain: &'static Chain,

}

impl PartialEq for Spork {
    fn eq(&self, other: &Self) -> bool {
        self.chain == other.chain &&
            self.identifier == other.identifier &&
            self.value == other.value &&
            self.time_signed == other.time_signed &&
            self.is_valid == other.is_valid
    }
}

impl Spork {

    pub fn is_equal_to_spork(&self, spork: &Spork) -> bool {
        self.chain == spork.chain &&
            self.identifier == spork.identifier &&
            self.value == spork.value &&
            self.time_signed == spork.time_signed &&
            self.is_valid == self.is_valid
    }

    pub fn key(&self) -> Option<&str> {
        self.chain.spork().public_key_hex_string
            .or(self.chain.spork().private_key_base58_string
                .and_then(|value| ECDSAKey::init_with_private_key(&value.to_string(), &self.chain)
                    .map(|private_key| private_key.pubkey.to_hex().as_str())))
    }

    /// starting in 12.3 sporks use addresses instead of public keys
    pub fn address(&self) -> &str {
        self.chain.spork().address
    }


    fn check_signature_70208_method(&self, signature: &Vec<u8>) -> bool {
        let string_message = format!("{:?}{}{}", self.identifier, self.value, self.time_signed);
        let mut buffer: Vec<u8> = Vec::new();
        DASH_MESSAGE_MAGIC.to_string().enc(&mut buffer);
        string_message.enc(&mut buffer);
        let message_digest = UInt256::sha256d(&buffer);
        let message_public_key = ECDSAKey::init_with_compact_sig(signature, message_digest);
        let spork_public_key = ECDSAKey::init_with_public_key(Vec::from_hex(self.key().unwrap()).unwrap());
        spork_public_key.unwrap().public_key_data() == message_public_key.unwrap().public_key_data()
    }


    pub fn check_signature(&self, signature: &Vec<u8>) -> bool {
        if self.chain.params.protocol_version < 70209 {
            self.check_signature_70208_method(signature)
        } else {
            let mut msg_public_key = ECDSAKey::init_with_compact_sig(signature, self.calculate_spork_hash()).unwrap();
            let spork_address = Address::with_public_key_data(&msg_public_key.public_key_data(), self.chain.script());
            self.address() == spork_address.as_str() ||
                (!self.chain.spork_manager().sporks_updated_signatures() && self.check_signature_70208_method(signature))
        }
    }

    pub fn calculate_spork_hash(&self) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::with_capacity(4 + 8 + 8);
        let id: u16 = self.identifier.into();
        id.enc(&mut buffer);
        self.value.enc(&mut buffer);
        self.time_signed.enc(&mut buffer);
        UInt256::sha256d(&buffer)
    }

    pub fn init_from_message(bytes: &[u8], chain: &Chain) -> Self {
        let offset = &mut 0;
        let identifier = bytes.read_with::<Identifier>(offset, LE).unwrap();
        let value = bytes.read_with::<u64>(offset, LE).unwrap();
        let time_signed = bytes.read_with::<u64>(offset, LE).unwrap();
        let signature_length = bytes.read_with::<VarInt>(offset, LE).unwrap().0 as usize;
        let signature_bytes: &[u8] = bytes.read_with(offset, Bytes::Len(signature_length)).unwrap();
        let signature = signature_bytes.to_vec();
        let mut spork = Spork {
            identifier,
            is_valid: false,
            time_signed,
            value,
            signature,
            chain
        };
        spork.is_valid = spork.check_signature(&signature);
        spork
    }
}

impl Spork {

    // pub fn update_values_with_hash<T, V>(&self, hash: &UInt256) -> Box<dyn EntityUpdates<V>>
    //     where T: Table,
    //           V: AsChangeset<Target=T> {
    pub fn update_values_with_hash(&self, hash: &UInt256) -> Box<dyn EntityUpdates<bool, ResultType = (bool, )>> {
        let mut values = self.update_values();
        Box::new(values.append(sporks::spork_hash.eq(hash)))
    }

    pub fn update_values(&self) -> Box<dyn EntityUpdates<bool, ResultType = (bool, )>> {
        Box::new((
            sporks::identifier.eq(self.identifier.into() as i32),
            sporks::signature.eq(&self.signature),
            sporks::time_signed.eq(self.time_signed as i64),
            sporks::value.eq(self.value as i64)
        ))
    }

    pub fn to_entity_with_hash<T, U>(&self, hash: UInt256, chain_id: i32) -> U
        where
            T: Table,
            T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            U: Insertable<T>,
            U::Values: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> + diesel::insertable::CanInsertInSingleQuery<diesel::sqlite::Sqlite> {
        let mut new_entity: NewSporkEntity = self.to_entity();
        new_entity.spork_hash = hash.clone();
        new_entity.chain_id = chain_id;
        new_entity
    }

    pub fn to_entity<T, U>(&self) -> U
        where
            T: Table,
            T::FromClause: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite>,
            U: Insertable<T>,
            U::Values: diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> + diesel::insertable::CanInsertInSingleQuery<diesel::sqlite::Sqlite> {
        NewSporkEntity {
            identifier: self.identifier.into() as i32,
            time_signed: self.time_signed as i64,
            value: self.value as i64,
            signature: self.signature.clone(),
            ..Default::default()
        }
    }

    pub fn from_entity(entity: &SporkEntity, chain: &Chain) -> Self {
        Self {
            identifier: Identifier::from(entity.identifier),
            is_valid: true,
            time_signed: entity.time_signed as u64,
            value: entity.value as u64,
            signature: entity.signature.clone(),
            chain
        }
    }
}

impl Spork {
    pub fn feature_is_activated(&mut self) -> bool {
        self.value <= self.chain.last_terminal_block_height() as u64
    }
}



// impl<'a> TryRead<'a, Endian> for Spork {
//     fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
//         let offset = &mut 0;
//         let identifier = bytes.read_with::<Identifier>(offset, endian).unwrap();
//         let value = bytes.read_with::<u64>(offset, endian).unwrap();
//         let time_signed = bytes.read_with::<u64>(offset, endian).unwrap();
//         let signature_length = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
//         let signature: &[u8] = bytes.read_with(offset, Bytes::Len(signature_length))?;
//         let spork = Spork {
//             identifier,
//             is_valid: false,
//             time_signed,
//             value,
//             signature: signature.to_vec(),
//             chain: None
//         };
//         Ok((spork, *offset))
//     }
// }
