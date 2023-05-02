use serde::{Deserialize, Serialize};
use crate::crypto::UInt256;

#[derive(Debug, Serialize, Deserialize)]
pub struct Records {
    #[serde(rename = "dashUniqueIdentityId")]
    pub dash_unique_identity_id: UInt256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubdomainRules {
    #[serde(rename = "allowSubdomains")]
    pub allow_subdomains: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DomainRequestJson {
    pub label: String,
    #[serde(rename = "normalizedLabel")]
    pub normalized_label: String,
    #[serde(rename = "normalizedParentDomainName")]
    pub normalized_parent_domain_name: String,
    #[serde(rename = "preorderSalt")]
    pub preorder_salt: UInt256,
    pub records: Records,
    #[serde(rename = "subdomainRules")]
    pub subdomain_rules: SubdomainRules,
}

impl DomainRequestJson {
    pub fn with_identity_unique_id(
        unique_id: UInt256,
        allow_subdomains: bool,
        label: String,
        normalized_label: String,
        normalized_parent_domain_name: String,
        preorder_salt: UInt256) -> Self {
        Self {
            label,
            normalized_label,
            normalized_parent_domain_name,
            preorder_salt,
            records: Records { dash_unique_identity_id: unique_id },
            subdomain_rules: SubdomainRules { allow_subdomains }
        }
    }
}
