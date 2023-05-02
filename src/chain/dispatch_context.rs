use std::future::Future;

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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DispatchContextType {
    Global,
    #[default]
    Main,
    Identity,
    Network,
}

#[derive(Clone, Debug, Default)]
pub struct DispatchContext {
    //todo
    pub r#type: DispatchContextType,
    // main_context: &'static DispatchContext,
}

impl<'a> Default for &'a DispatchContext {
    fn default() -> Self {
        &DispatchContext::default()
    }
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
    pub fn global_context() -> Self {
        Self::new(DispatchContextType::Global)
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

    pub fn queue<T>(&self, task: impl Fn() -> T) -> T {
        // todo: use context queue to publish result
        task()
    }

    pub async fn async_queue<T: Future + Send>(&self, mut task: impl FnMut() -> T) -> T {
        // todo: use context queue to publish result
        task()
    }



    pub fn after<T, E>(&self, time: DispatchTime, mut task: impl FnMut() -> T) -> T {
        // todo: dispatch after timeout
        task()
    }
}
