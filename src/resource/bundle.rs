use std::{env, fs};
use std::io::Read;
use crate::platform::contract::ContractType;

#[derive(Debug, Default)]
pub struct Bundle {

}

impl Bundle {
    // pub fn languages(&self) -> Vec<>

    pub fn load_words(&self) -> Vec<String> {
        vec![]
    }

    pub fn load_contract_scheme(&self, r#type: ContractType) -> serde_json::Value  {
        let data = Self::message_from_file(r#type.filename().to_string());
        serde_json::to_value(data).unwrap()
    }
}

impl Bundle {
    pub fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
        //println!("get_file_as_byte_vec: {}", filename);
        let mut f = fs::File::open(&filename).expect("no file found");
        let metadata = fs::metadata(&filename).expect("unable to read metadata");
        let mut buffer = vec![0; metadata.len() as usize];
        f.read_exact(&mut buffer).expect("buffer overflow");
        buffer
    }

    pub fn message_from_file(name: String) -> Vec<u8> {
        let executable = env::current_exe().unwrap();
        let path = match executable.parent() {
            Some(name) => name,
            _ => panic!(),
        };
        let filepath = format!("{}/../../../files/{}", path.display(), name.as_str());
        println!("{:?}", filepath);
        Self::get_file_as_byte_vec(&filepath)
    }

}
