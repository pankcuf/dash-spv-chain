bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MonitorOptions: u32 {
        const None = 0;
        const AcceptNotFoundAsNotAnError = 1;
    }
}
