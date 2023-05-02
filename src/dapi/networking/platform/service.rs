use crate::crypto::UInt256;
use crate::chain::dispatch_context::DispatchContext;
use crate::dapi::networking::platform::dto::contract_info::ContractInfo;
use crate::dapi::networking::platform::dto::identity::IdentityDTO;
use crate::platform::identity::contact_request::ContactRequestJson;
use crate::platform::identity::domain_request::DomainRequestJson;
use crate::platform::identity::preorder_request::PreorderRequest;
use crate::util;

#[derive(Debug, Default)]
pub struct Service {
    pub ip_address: String,
}

impl Service {

    pub async fn fetch_contract_for_id(&self, data: Vec<u8>, dispatch_context: &DispatchContext) -> Result<ContractInfo, util::Error> {
        // spawn_blocking(move || {
        //     let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
        //     socket.bind(&bind)?;
        //     socket.connect(&connect)?;
        //     TcpStream::from_std(socket.into_tcp_stream())
        // }).await?
        todo!()
    }

    pub async fn get_dpns_documents_for_identity_with_user_id(&self, user_id: &UInt256, dispatch_context: &DispatchContext) -> Result<Vec<DomainRequestJson>, util::Error> {
        todo!()
    }

    pub async fn get_dpns_documents_for_usernames_in_domain(&self, usernames: &Vec<String>, domain: &String, dispatch_context: &DispatchContext) -> Result<Vec<DomainRequestJson>, util::Error> {
        todo!()
    }

    pub async fn get_dpns_documents_for_preorder_salted_domain_hashes(&self, salted_domain_hashes: Vec<UInt256>, dispatch_context: &DispatchContext) -> Result<Vec<PreorderRequest>, util::Error> {
        todo!()
    }

    pub async fn get_identity_by_id(&self, user_id: &UInt256, dispatch_context: &DispatchContext) -> Result<IdentityDTO, util::Error> {
        todo!()
    }

    pub async fn get_identity_by_name(&self, name: &String, domain: &String, dispatch_context: &DispatchContext) -> Result<IdentityDTO, util::Error> {
        todo!()
    }

    pub async fn get_dashpay_incoming_contact_requests_for_user_id(&self, user_id: &UInt256, since: u64, start_after: Option<Vec<u8>>, dispatch_context: &DispatchContext) -> Result<Vec<ContactRequestJson>, util::Error> {
        todo!()
    }

}
