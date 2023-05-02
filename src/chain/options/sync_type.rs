// pub enum SyncType {
//     None = 0,
//     BaseSPV = 1,
//     FullBlocks = 1 << 1,
//     Mempools = 1 << 2,
//     SPV = SyncType::BaseSPV | SyncType::Mempools,
//     MasternodeList = 1 << 3,
//     VerifiedMasternodeList = SyncType::MasternodeList | SyncType::SPV,
//     Governance = 1 << 4,
//     GovernanceVotes = 1 << 5,
//     GovernanceVoting = SyncType::Governance | SyncType::MasternodeList,
//     Sporks = 1 << 6,
//     BlockchainIdentities = 1 << 7,
//     DPNS = 1 << 8,
//     Dashpay = 1 << 9,
//     MultiAccountAutoDiscovery = 1 << 10,
//     Default = SyncType::SPV | SyncType::Mempools | SyncType::VerifiedMasternodeList | SyncType::Sporks | SyncType::BlockchainIdentities | SyncType::DPNS | SyncType::Dashpay | SyncType::MultiAccountAutoDiscovery,
//     NeedsWalletSyncType = SyncType::BaseSPV | SyncType::FullBlocks,
//     GetsNewBlocks = SyncType::SPV | SyncType::FullBlocks,
// }

// pub mod SyncType {
//     pub const None: u8 = 0;
//     pub const BaseSPV: u8 = 1;
//     pub const FullBlocks: u8 = 1 << 1;
//     pub const Mempools: u8 = 1 << 2;
//     pub const SPV: u8 = BaseSPV | Mempools;
//     pub const MasternodeList: u8 = 1 << 3;
//     pub const VerifiedMasternodeList: u8 = MasternodeList | SPV;
//     pub const Governance: u8 = 1 << 4;
//     pub const GovernanceVotes: u8 = 1 << 5;
//     pub const GovernanceVoting: u8 = Governance | MasternodeList;
//     pub const Sporks: u8 = 1 << 6;
//     pub const BlockchainIdentities: u8 = 1 << 7;
//     pub const DPNS: u8 = 1 << 8;
//     pub const Dashpay: u8 = 1 << 9;
//     pub const MultiAccountAutoDiscovery: u8 = 1 << 10;
//     pub const Default: u8 = SPV | Mempools | VerifiedMasternodeList | Sporks | BlockchainIdentities | DPNS | Dashpay | MultiAccountAutoDiscovery;
//     pub const NeedsWalletSyncType: u8 = BaseSPV | FullBlocks;
//     pub const GetsNewBlocks: u8 = SPV | FullBlocks;
//
// }

bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct SyncType: u8 {
        const None = 0;
        const BaseSPV = 1;
        const FullBlocks = 1 << 1;
        const Mempools = 1 << 2;
        const SPV = Self::BaseSPV.bits() | Self::Mempools.bits();
        const MasternodeList = 1 << 3;
        const VerifiedMasternodeList = Self::MasternodeList.bits() | Self::SPV.bits();
        const Governance = 1 << 4;
        const GovernanceVotes = 1 << 5;
        const GovernanceVoting = Self::Governance.bits() | Self::MasternodeList.bits();
        const Sporks = 1 << 6;
        const BlockchainIdentities = 1 << 7;
        const DPNS = 1 << 8;
        const Dashpay = 1 << 9;
        const MultiAccountAutoDiscovery = 1 << 10;
        const Default = Self::SPV.bits() | Self::Mempools.bits() | Self::VerifiedMasternodeList.bits() | Self::Sporks.bits() | Self::BlockchainIdentities.bits() | Self::DPNS.bits() | Self::Dashpay.bits() | Self::MultiAccountAutoDiscovery.bits();
        const NeedsWalletSyncType = Self::BaseSPV.bits() | Self::FullBlocks.bits();
        const GetsNewBlocks = Self::SPV.bits() | Self::FullBlocks.bits();
    }
}
