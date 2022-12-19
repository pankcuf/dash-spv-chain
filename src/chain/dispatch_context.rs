use std::thread;

pub struct DispatchTime {
    pub time: u64,
}

impl DispatchTime {
    pub fn new(after: u64, delta: u64) -> Self {
        todo!()
    }
    pub fn delay(delay: u64) -> Self {
        todo!()
    }
}

pub enum DispatchContextType {
    Global,
    Main,
    Identity,
    Network,
}

pub struct DispatchContext {
    //todo
    pub r#type: DispatchContextType,
    // main_context: &'static DispatchContext,
}

impl DispatchContext {
    pub fn new(r#type: DispatchContextType) -> Self {
        Self { r#type }
    }
    pub fn main_context() -> Self {
        Self::new(DispatchContextType::Main)
    }

    pub fn network_context() -> Self {
        Self::new(DispatchContextType::Network)
    }

    pub fn flow(tasks: Vec<fn(&DispatchContext)>, context: &DispatchContext) {
        //todo: impl dispatch_group_t functionality
        tasks.iter().for_each(|task| {
            // thread::spawn()
            task(context);
        });
    }

    pub fn post<T, E>(&self, result: Result<T, E>) -> Result<T, E> {
        // todo: use context queue to publish result
        result
    }

    pub fn queue<T>(&self, task: fn() -> T) -> T {
        // todo: use context queue to publish result
        task()
    }

    pub fn after<T, E>(&self, time: DispatchTime) -> fn(Self) {
        // todo: dispatch after timeout
    }
}
