use crate::platform::contract::contract::Contract;

pub struct DocumentType {
    pub name: String,
    pub contract_index: u8,
    pub path: Vec<Vec<u8>>,
    pub serialized_path: Vec<u8>,
    pub contract: Contract,

    @property (readonly, nonatomic) NSString *name;
    @property (readonly, nonatomic) uint8_t contractIndex;
    @property (readonly, nonatomic) NSArray<NSData *> *path;
    @property (readonly, nonatomic) NSData *serializedPath;
    @property (readonly, nonatomic, weak) DPContract *contract;
    @property (readonly, nonatomic) NSArray<NSData *> *mainIndexPath;
    @property (readonly, nonatomic) NSArray<NSArray<NSData *> *> *secondaryIndexPaths;

}
