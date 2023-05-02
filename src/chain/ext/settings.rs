use crate::chain::Chain;
use crate::chain::params::{BIP32ScriptMap, DIP14ScriptMap, ScriptMap, SporkParams};

pub trait Settings {
    fn script(&self) -> &ScriptMap;
    fn bip32(&self) -> &BIP32ScriptMap;
    fn dip14(&self) -> &DIP14ScriptMap;
    fn spork(&self) -> &SporkParams;
}

impl Settings for Chain {
    fn script(&self) -> &ScriptMap {
        &self.params.script_map
    }

    fn bip32(&self) -> &BIP32ScriptMap {
        &self.params.bip32_script_map
    }

    fn dip14(&self) -> &DIP14ScriptMap {
        &self.params.dip14_script_map
    }

    fn spork(&self) -> &SporkParams {
        &self.params.spork_params
    }
}
