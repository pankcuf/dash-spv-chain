// pub enum FriendshipStatus {
//     Unknown = isize::MAX,
//     None = 0,
//     Outgoing = 1,
//     Incoming = 2,
//     Friends = 1 | 2,
// }

bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct FriendshipStatus: u8 {
        const Unknown = u8::MAX;
        const None = 0;
        const Outgoing = 1;
        const Incoming = 2;
        const Friends = FriendshipStatus::Outgoing.bits() | FriendshipStatus::Incoming.bits();
    }
}

impl From<i16> for FriendshipStatus {
    fn from(orig: i16) -> Self {
        #[allow(unused_parens)]
        match orig {
            0 => FriendshipStatus::None,
            1 => FriendshipStatus::Outgoing,
            2 => FriendshipStatus::Incoming,
            (1 | 2) => FriendshipStatus::Friends,
            _ => FriendshipStatus::Unknown,
        }
    }
}

impl From<FriendshipStatus> for i16 {
    fn from(value: FriendshipStatus) -> Self {
        match value {
            FriendshipStatus::Unknown => i16::MAX,
            FriendshipStatus::None => 0,
            FriendshipStatus::Outgoing => 1,
            FriendshipStatus::Incoming => 2,
            FriendshipStatus::Friends => (FriendshipStatus::Outgoing.bits() | FriendshipStatus::Incoming.bits()).into(),
        }
    }
}
