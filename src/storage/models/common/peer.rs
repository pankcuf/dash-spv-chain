use std::collections::HashSet;
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, Insertable, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::chain::Chain;
use crate::chain::common::ChainType;
use crate::chain::network::Peer;
use crate::crypto::UInt128;
use crate::schema::peers;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::Entity;

/// queries:
/// "chain == %@"
/// "chain == %@ && (((address >> %@) & 255) == %@)"
/// "(chain == %@) && !(address in %@)"
/// "(chain == %@) && (address in %@)"
/// "address == %@ && port == %@"
/// indexation:
/// ["priority": DESC, "address": ASC]

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = peers)]
pub struct PeerEntity {
    pub id: i32,
    pub address: i32,
    pub port: i16,
    pub misbehaving: i16,
    pub priority: i32,
    pub services: i64,
    pub timestamp: NaiveDateTime,
    pub last_requested_governance_sync: NaiveDateTime,
    pub last_requested_masternode_list: NaiveDateTime,
    pub low_preference_till: NaiveDateTime,

    pub chain_id: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = peers)]
pub struct NewPeerEntity {
    pub address: i32,
    pub port: i16,
    pub misbehaving: i16,
    pub priority: i32,
    pub services: i64,
    pub timestamp: NaiveDateTime,
    pub last_requested_governance_sync: NaiveDateTime,
    pub last_requested_masternode_list: NaiveDateTime,
    pub low_preference_till: NaiveDateTime,

    pub chain_id: i32,
}

impl Entity for PeerEntity {
    type ID = peers::id;
    // type ChainId = peers::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        peers::dsl::peers
    }
}

/*impl EntityConvertible for PeerEntity {
    fn new_entity<T, U>(&self) -> U where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite>, U: Insertable<T>, diesel::insertable::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {
        todo!()
    }

    fn update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>> where T: Table, V: AsChangeset<Target=T> {
        todo!()
    }

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> {
        __block DSPeer *peer = nil;
        [self.managedObjectContext performBlockAndWait:^{
            UInt128 address = {.u32 = {0, 0, CFSwapInt32HostToBig(0xffff), CFSwapInt32HostToBig(self.address)}};
            DSChain *chain = [self.chain chain];
            peer = [[DSPeer alloc] initWithAddress:address port:self.port onChain:chain timestamp:self.timestamp services:self.services];
            peer.misbehaving = self.misbehavin;
            peer.priority = self.priority;
            peer.lowPreferenceTill = self.lowPreferenceTill;
            peer.lastRequestedMasternodeList = self.lastRequestedMasternodeList;
        }];
        return peer;
    }
}*/

impl PeerEntity {
    pub fn peer(&self, chain: &Chain) -> Peer {
        let address = UInt128::ip_address_from_i32(self.address);
        let mut p = Peer::new(address, self.port as u16, self.timestamp.timestamp() as u64, self.services as u64, chain);
        p.misbehaving = self.misbehaving;
        p.priority = self.priority as u32;
        p.low_preference_till = self.low_preference_till.timestamp() as u64;
        p.last_requested_masternode_list = Some(self.last_requested_masternode_list.timestamp() as u64);
        p
    }

}

impl PeerEntity {
    pub fn get_all_peers_for_chain(chain_type: ChainType, context: &ManagedContext) -> QueryResult<Vec<PeerEntity>> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity|
                PeerEntity::read(peers::chain_id.eq(chain_entity.id), context))
    }


    pub fn delete_all_peers_for_chain(chain_type: ChainType, context: &ManagedContext) -> QueryResult<usize> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity|
                PeerEntity::delete_by(peers::chain_id.eq(chain_entity.id), context))
    }

    pub fn delete_peers_except_list(chain_type: ChainType, addresses: &Vec<i32>, context: &ManagedContext) -> QueryResult<usize> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity|
                Self::delete_by(peers::chain_id.eq(chain_entity.id).and(peers::address.ne_all(addresses)), context))
    }

    pub fn update_with_peer(&self, peer: &Peer, context: &ManagedContext) -> QueryResult<usize> {
        self.update_with(peer.update_values(), context)
    }

    pub fn get_peers_with_addresses_for_chain_type(chain_type: ChainType, addresses: &Vec<i32>, context: &ManagedContext) -> QueryResult<Vec<PeerEntity>> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity|
                Self::read(peers::chain_id.eq(chain_entity.id).and(peers::address.eq_any(addresses)), context))
    }

    pub fn get_peers_with_addresses_for_chain(chain_entity: &ChainEntity, addresses: &Vec<i32>, context: &ManagedContext) -> QueryResult<Vec<PeerEntity>> {
        let predicate = peers::chain_id.eq(chain_entity.id).and(peers::address.eq_any(addresses));
        Self::read(predicate, context)
    }

    pub fn create_from_peers(peers: HashSet<Peer>, chain_id: i32, context: &ManagedContext) -> QueryResult<Vec<PeerEntity>> {
        let new_entities = peers.iter().map(|p| p.create_entity(chain_id)).collect();
        Self::create_many(new_entities, context)
    }
}
