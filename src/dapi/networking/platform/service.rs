use std::collections::HashMap;
use crate::crypto::{UInt128, UInt256};
use crate::chain::dispatch_context::DispatchContext;
use crate::platform::base::serializable_object::{SerializableKey, SerializableValue};
use crate::platform::contract::contract::Contract;
use crate::platform::identity::contact_request::ContactRequestJson;

#[derive(Debug)]
pub struct Service {
    pub ip_address: &'static String,
}

impl Service {

    pub async fn fetch_contract_for_id(&self, data: &Vec<u8>, dispatch_context: &DispatchContext) -> Result<HashMap<String, dyn SerializableValue>, Error> {
        // spawn_blocking(move || {
        //     let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
        //     socket.bind(&bind)?;
        //     socket.connect(&connect)?;
        //     TcpStream::from_std(socket.into_tcp_stream())
        // }).await?
        todo!()
    }

    pub async fn get_dpns_documents_for_identity_with_user_id(&self, user_id: &UInt256, dispatch_context: &DispatchContext) -> Result<Vec<HashMap<dyn SerializableKey, dyn SerializableValue>>, Error> {
        todo!()
    }

    pub async fn get_dpns_documents_for_usernames_in_domain(&self, usernames: &Vec<String>, domain: &String, dispatch_context: &DispatchContext) -> Result<Vec<HashMap<dyn SerializableKey, dyn SerializableValue>>, Error> {
        todo!()
    }

    pub async fn get_dpns_documents_for_preorder_salted_domain_hashes(&self, salted_domain_hashes: &Vec<String>, dispatch_context: &DispatchContext) -> Result<Vec<HashMap<dyn SerializableKey, dyn SerializableValue>>, Error> {
        todo!()
    }

    pub async fn get_identity_by_id(&self, user_id: &UInt256, dispatch_context: &DispatchContext) -> Result<HashMap<dyn SerializableKey, dyn SerializableValue>, Error> {
        todo!()
    }

    pub async fn get_identity_by_name(&self, name: &String, domain: &String, dispatch_context: &DispatchContext) -> Result<HashMap<dyn SerializableKey, dyn SerializableValue>, Error> {
        todo!()
    }

    pub async fn get_dashpay_incoming_contact_requests_for_user_id(&self, user_id: &UInt256, since: u64, start_after: Option<Vec<u8>>, dispatch_context: &DispatchContext) -> Result<Vec<ContactRequestJson>, Error> {
        todo!()
    }

}
