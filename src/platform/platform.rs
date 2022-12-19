use std::collections::HashMap;
use crate::chain::chain::Chain;
use crate::platform::base::serializable_object::SerializableKey;
use crate::platform::contract::contract::Contract;
use crate::platform::document;
use crate::platform::identity::identity::Identity;

pub enum ContractType {
    DPNSContract,
    DashPayContract,
    DashThumbnailContract,
}

impl SerializableKey for ContractType {
    fn as_str(&self) -> &str {
        match self {
            ContractType::DPNSContract => "DPNS_CONTRACT",
            ContractType::DashPayContract => "DASHPAY_CONTRACT",
            ContractType::DashThumbnailContract => "DASHTHUMBNAIL_CONTRACT",
        }
    }
}

impl ContractType {
    fn name(&self) -> &str {
        match self {
            ContractType::DPNSContract => "DPNS",
            ContractType::DashPayContract => "DashPay",
            ContractType::DashThumbnailContract => "DashThumbnail",
            _ => "Unnamed Contract",
        }
    }
}

pub struct Platform {
    pub chain: &'static Chain,
    known_contracts: HashMap<ContractType, &'static Contract>,

    pub dash_pay_contract: Contract,
    pub dpns_contract: Contract,
    pub dash_thumbnail_contract: Contract,
}

impl Platform {
    pub fn new(chain: &Chain) -> Self {
        let dash_pay_contract = Contract::localDashpayContractForChain(chain);
        let dpns_contract = Contract::localDPNSContractForChain(chain);
        let dash_thumbnail_contract = Contract::localDashThumbnailContractForChain(chain);
        Self {
            chain,
            dash_pay_contract,
            dpns_contract,
            dash_thumbnail_contract,
            known_contracts: HashMap::from([
                (ContractType::DashPayContract, &dash_pay_contract),
                (ContractType::DPNSContract, &dpns_contract),
                (ContractType::DashThumbnailContract, &dash_thumbnail_contract),
            ])
        }
    }

    pub fn document_factory_for_identity_id(&self, identity: &Identity, contract: &Contract) -> document::Factory {
        document::Factory::new(identity, contract, self.chain)
    }

    pub fn name_for_contract_with_identifier(identifier: &String) -> String {
        if identifier.starts_with(DASHPAY_CONTRACT) {
            "DashPay"
        } else if identifier.starts_with(DPNS_CONTRACT) {
            "DPNS"
        } else if identifier.starts_with(DASHTHUMBNAIL_CONTRACT) {
            "DashThumbnail"
        } else {
            "Unnamed Contract"
        }.to_string()
    }

    pub fn known_contracts(&self) -> &HashMap<ContractType, &Contract> {
        &self.known_contracts
    }


}
