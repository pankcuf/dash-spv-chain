#[derive(Debug, Eq, Hash, PartialEq)]
pub enum ContractType {
    DAC,
    DashPay,
    DashThumbnail,
    DPNS,
}

impl From<ContractType> for String {
    fn from(value: ContractType) -> Self {
        match value {
            ContractType::DAC => "DAC_CONTRACT",
            ContractType::DPNS => "DPNS_CONTRACT",
            ContractType::DashPay => "DASHPAY_CONTRACT",
            ContractType::DashThumbnail => "DASHTHUMBNAIL_CONTRACT",
        }.to_string()
    }
}

impl ContractType {
    pub fn name(&self) -> &str {
        match self {
            ContractType::DAC => "DAC",
            ContractType::DPNS => "DPNS",
            ContractType::DashPay => "DashPay",
            ContractType::DashThumbnail => "DashThumbnail",
            _ => "Unnamed Contract",
        }
    }
    pub fn filename(&self) -> &str {
        match self {
            ContractType::DAC => "dac-contract.json",
            ContractType::DPNS => "dpns-contract.json",
            ContractType::DashPay => "dashpay-contract.json",
            ContractType::DashThumbnail => "dashthumbnail-contract.json",
        }
    }
}
