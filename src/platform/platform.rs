use std::collections::HashMap;
use crate::chain::chain::Chain;
use crate::platform::contract::contract::Contract;
use crate::platform::contract::ContractType;
use crate::platform::document;
use crate::platform::identity::identity::Identity;

#[derive(Debug, Default)]
pub struct Platform {
    pub chain: &'static Chain,
    known_contracts: HashMap<ContractType, &'static Contract>,

    pub dash_pay_contract: Contract,
    pub dpns_contract: Contract,
    pub dash_thumbnail_contract: Contract,
}

impl Platform {
    pub fn new(chain: &Chain) -> Self {
        let dash_pay_contract = Contract::local_dashpay_contract_for_chain(chain);
        let dpns_contract = Contract::local_dpns_contract_for_chain(chain);
        let dash_thumbnail_contract = Contract::local_dash_thumbnail_contract_for_chain(chain);
        Self {
            chain,
            dash_pay_contract,
            dpns_contract,
            dash_thumbnail_contract,
            known_contracts: HashMap::from([
                (ContractType::DashPay, &dash_pay_contract),
                (ContractType::DPNS, &dpns_contract),
                (ContractType::DashThumbnail, &dash_thumbnail_contract),
            ])
        }
    }

    pub fn document_factory_for_identity_id(&self, identity: &Identity, contract: &Contract) -> document::Factory {
        document::Factory::new(identity, contract, self.chain)
    }

    pub fn name_for_contract_with_identifier(identifier: &String) -> String {
        if identifier.starts_with(&String::from(ContractType::DashPay)) {
            ContractType::DashPay.name()
        } else if identifier.starts_with(&String::from(ContractType::DPNS)) {
            ContractType::DPNS.name()
        } else if identifier.starts_with(&String::from(ContractType::DashThumbnail)) {
            ContractType::DashThumbnail.name()
        } else {
            "Unnamed Contract"
        }.to_string()
    }

    pub fn known_contracts(&self) -> &HashMap<ContractType, &Contract> {
        &self.known_contracts
    }


}
