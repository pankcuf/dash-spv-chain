pub enum FriendshipStatus {
    Unknown = isize::MAX,
    None = 0,
    Outgoing = 1,
    Incoming = 2,
    Friends = FriendshipStatus::Outgoing | FriendshipStatus::Incoming,
}

impl From<i16> for FriendshipStatus {
    fn from(orig: i16) -> Self {
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
            FriendshipStatus::Friends => FriendshipStatus::Outgoing | FriendshipStatus::Incoming,
        }
    }
}
