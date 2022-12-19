use bitcoin_hashes::hex::FromHex;
use crate::chain::common::chain_type::DevnetType;
use crate::chain::tx::Transaction;
use crate::crypto::byte_util::Reversable;
use crate::crypto::UInt256;

/// blockchain checkpoints - these are also used as starting points for partial chain downloads,
/// so they need to be at difficulty transition boundaries in order to verify the block
/// difficulty at the immediately following transition
pub struct Checkpoint {
    pub height: u32,
    pub hash: UInt256,
    pub timestamp: u32,
    pub target: u32,
    pub masternode_list_path: String,
    pub merkle_root: UInt256,
    pub chain_work: UInt256,
}

impl Checkpoint {
    pub fn new(height: u32, hash: &str, timestamp: u32, target: u32, masternode_list_path: &str, merkle_root: &str, chain_work: &str) -> Self {
        Self {
            height,
            hash: UInt256::from_hex(hash).unwrap(),
            timestamp,
            target,
            masternode_list_path: masternode_list_path.to_string(),
            merkle_root: UInt256::from_hex(merkle_root).unwrap(),
            chain_work: UInt256::from_hex(chain_work).unwrap()
        }
    }

    pub fn genesis_devnet_checkpoint() -> Self {
        Self {
            height: 0,
            hash: UInt256::from_hex("000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e").unwrap().reversed(),
            timestamp: 1417713337,
            target: 0x207fffff,
            masternode_list_path: "".to_string(),
            merkle_root: Default::default(),
            chain_work: UInt256::from_hex("0200000000000000000000000000000000000000000000000000000000000000").unwrap()
        }
    }

    pub fn create_dev_net_genesis_block_checkpoint_for_parent_checkpoint(
        checkpoint: Checkpoint,
        r#type: DevnetType,
        protocol_version: u32) -> Self {
        let version = r#type.version();
        let identifier = r#type.identifier();
        let nTime: u32 = checkpoint.timestamp + 1;
        let nBits: u32 = checkpoint.target;
        let fullTarget: UInt256 = setCompactLE(nBits);
        let nVersion: u32 = 4;
        let prevHash = checkpoint.hash;
        let merkle_root = Transaction::devnet_genesis_coinbase_with_identifier(identifier, version, protocol_version,)
        UInt256 merkleRoot = [DSTransaction devnetGenesisCoinbaseWithIdentifier:identifier version:version onProtocolVersion:protocolVersion forChain:self].txHash;
        let chainWork = UInt256::from_hex("0400000000000000000000000000000000000000000000000000000000000000").unwrap();
        let nonce = u32::MAX; //+1 => 0;
        let block_hash: UInt256;

        while  {

        }

        do {
            nonce++; //should start at 0;
            blockhash = [self blockHashForDevNetGenesisBlockWithVersion:nVersion prevHash:prevHash merkleRoot:merkleRoot timestamp:nTime target:nBits nonce:nonce];
        } while (nonce < UINT32_MAX && uint256_sup(blockhash, fullTarget));
        DSCheckpoint *block2Checkpoint = [DSCheckpoint checkpointForHeight:1 blockHash:blockhash timestamp:nTime target:nBits merkleRoot:merkleRoot chainWork:chainWork masternodeListName:nil];


        Checkpoint {
            height: 1,
            hash: block_hash,
            timestamp: nTime,
            target: nBits,
            masternode_list_path: "".to_string(),
            merkle_root: Default::default(),
            chain_work: Default::default()
        }

    }
}

pub const TESTNET_CHECKPOINT_ARRAY: Vec<Checkpoint> = vec![
    Checkpoint::new(0, "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c", 1390666206, 0x1e0ffff0, "", "", "0000000000000000000000000000000000000000000000000000000000100010"),
    Checkpoint::new(1500, "000002d7a07979a4d6b24efdda0bbf6e3c03a59c22765a0128a5c53b3888aa28", 1423460945, 0x1e03ffff, "", "", "000000000000000000000000000000000000000000000000000000009f403ba7"),
    Checkpoint::new(2000, "000006b9af71c8ac510ff912b632ff91a2e05ab92ba4de9f1ec4be424c4ba636", 1462833216, 0x1e0fffff, "", "", "00000000000000000000000000000000000000000000000000000001e81159d8"),
    Checkpoint::new(2999, "0000024bc3f4f4cb30d29827c13d921ad77d2c6072e586c7f60d83c2722cdcc5", 1462856598, 0x1e03ffff, "", "", "000000000000000000000000000000000000000000000000000000034dd286a4"),
    Checkpoint::new(4002, "00000534b6b0a7ba8746a412384c9c9bbd492e03e2babd2878f0723981f03978", 1544736464, 0x1e0fffff, "", "", "00000000000000000000000000000000000000000000000000000003cd92a544"),
    Checkpoint::new(8000, "0000001618273379c4d96403954480bdf5c522d734f457716db1295d7a3646e0", 1545231876, 0x1d1c3ba6, "", "", "000000000000000000000000000000000000000000000000000006f4c9b0f637"),
    Checkpoint::new(15000, "00000000172f1946aad9183732d65aaa117d47c2e86c698940bd942dc7ffccc5", 1546203631, 0x1c19907e, "", "", "0000000000000000000000000000000000000000000000000000fb8fdcfbec41"),
    Checkpoint::new(19500, "000000000735c41ba5948fbe6c791d5e28b02e3eff5ea4ac7fecf6d07c488edf", 1546803426, 0x1c0daf28, "", "", "0000000000000000000000000000000000000000000000000001ab8e4215dc59"),  //important for testInstantSendReceiveTransaction
    Checkpoint::new(122064, "0000000003fa1af7f55b5cde19da8c8fdb024a881a50794cd1c31e0cb4506b3d", 1561126213, 0x1c0c2849, "", "", "000000000000000000000000000000000000000000000000006a40236b40b0e8"), //for tests
    Checkpoint::new(122088, "0000000007eec28e1459b36de6e54ac81fa2dc2b12a797ac77ee7c7f7a59148f", 1561129080, 0x1c0839ad, "", "", "000000000000000000000000000000000000000000000000006a4265998db1b8"), //for tests
    Checkpoint::new(122928, "0000000001d975dfc73df9040e894576f27f6c252f1540b1c092c80353cdb823", 1561247926, 0x1c0b30d2, "", "", "000000000000000000000000000000000000000000000000006a81a7832f90bd"), //for tests
    Checkpoint::new(123000, "000000000577855d5599ce9a89417628233a6ccf3a86b2938b191f3dfed2e63d", 1561258020, 0x1c0d4446, "", "", "000000000000000000000000000000000000000000000000006a86c80a25f15c"), //for tests
    Checkpoint::new(180000, "000000000175f718920ecebd54765faee973975511415f1dd1ef12194518675b", 1569211090, 0x1c025786, "", "", "000000000000000000000000000000000000000000000000007f95dcdcbb22d6"),
    Checkpoint::new(300000, "00000059475b2de06486d86c1764ee6058b454eea72a32eb7f900aa94b9d4312", 1588424121, 0x1e0fffff, "", "", "00000000000000000000000000000000000000000000000001e6f6b99adb1c2b"),
    Checkpoint::new(370368, "000001702422af778c9d1e16a891f58fbaabb6ff82dea8fc1910ab80552bdf9c", 1598642620, 0x1e02336e, "", "717beedaa6da0d5c1124b9d0788d040ca18eb1fe6ed49c126ea9a2d30d11921c", "00000000000000000000000000000000000000000000000002239b4ac0e84dc4"), //for tests
    Checkpoint::new(414106, "00000674c5269b59d6d3bb6bb08b58add4b3e0eab11136be47bb8e0d4ec86e69", 1609043444, 0x1e0dd96e, "", "e8c45fabdb650ac2c42105083cb63998142e18be89b61bd034b3714498e6622f", "000000000000000000000000000000000000000000000000022f14058d3b2efc"),  //fork height
    Checkpoint::new(480000, "000001210c081f763d18db332b38ec1ac14fac62170a0d1a2028cabe8cecc799", 1618235036, 0x1e01eec7, "", "d9fae96cce9bf0edcf9ece1b7894e0356165c0a5dcdc6f2e0784461c4168cbec", "000000000000000000000000000000000000000000000000022f14bf215f8016"),
    Checkpoint::new(530000, "0000060db4b6bdb17f0617d15637bdf0f18ad738ccb438ee2cd000fef11c7130", 1625277934, 0x1e0fffff, "MNT530000", "7a6a78a22df2d9dc8c44afd48dfe4a60f75428f5e6004cf4cdf82e4f81a0a68b", "000000000000000000000000000000000000000000000000022f1524ad0dacd3"),
    Checkpoint::new(760000, "000000b80d3010bb62b309aec9a7dd748777cc5e2640a26b1981cb3c61c66211", 1657592023, 0x1e01f865, "", "8302c05bdca60e7dfcac26cebea8d797bda1b87111cf3a3dc33050c43f2abfbe", "000000000000000000000000000000000000000000000000027baba1fe003e84"),
];

pub const MAINNET_CHECKPOINT_ARRAY: Vec<Checkpoint> = vec![
    Checkpoint::new(0, "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6", 1390095618, 0x1e0ffff0, "", "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7", "0000000000000000000000000000000000000000000000000000000000100010"),
    Checkpoint::new(227121, "00000000000455a2b3a2ed5dfb03990043ca0074568b939acec62820e89a6c45", 1425039295, 0x1b1261d6, "", "", "00000000000000000000000000000000000000000000000021355b4a2f76e1f1"), //This is the first sync time (aka BIP39 creation time).
    Checkpoint::new(230000, "0000000000014a26211176f72564e442e01354d70b9bfdc4927f775127f7ccb4", 1425492298, 0x1b0e7bdd, "", "228e067496be60515f35b89a35fadc8bd91ea80f58b9ce2db3b94af36781e343", "00000000000000000000000000000000000000000000000021d5d06e1c6c822f"),
    Checkpoint::new(340000, "000000000014f4e32be2038272cc074a75467c342e25bfe0b566fabe927240b4", 1442833344, 0x1b1acd73, "", "", "00000000000000000000000000000000000000000000000034e3620e6971b1b8"),
    Checkpoint::new(400000, "00000000000132b9afeca5e9a2fdf4477338df6dcff1342300240bc70397c4bb", 1452288263, 0x1b0d642e, "", "", "00000000000000000000000000000000000000000000000040252b2b3b38ca28"),
    Checkpoint::new(500000, "000000000002be1cff717f4aa6efc504fa06dc9c453c83773de0b712b8690b7d", 1468042975, 0x1b06a6cf, "", "", "0000000000000000000000000000000000000000000000006609142fb25f3515"),
    Checkpoint::new(600000, "000000000000a0b730b5be60e65b4a730d1fdcf1d023c9e42c0e5bf4a059f709", 1483795508, 0x1b00db54, "", "", "0000000000000000000000000000000000000000000000014711b6a853f7dd94"),
    Checkpoint::new(620000, "0000000000002e7f2ab6cefe6f63b34c821e7f2f8aa5525c6409dc57677044b4", 1486948317, 0x1b0100c5, "", "", "000000000000000000000000000000000000000000000001a66418be0738eca2"),
    Checkpoint::new(640000, "00000000000079dfa97353fd50a420a4425b5e96b1699927da5e89cbabe730bf", 1490098758, 0x1b009c90, "", "", "0000000000000000000000000000000000000000000000021b9fe97b42a66316"),
    Checkpoint::new(660000, "000000000000124a71b04fa91cc37e510fabd66f2286491104ecf54f96148275", 1493250273, 0x1a710fe7, "", "", "0000000000000000000000000000000000000000000000029f6340553c5c2dc3"),
    Checkpoint::new(680000, "00000000000012b333e5ba8a85895bcafa8ad3674c2fb8b2de98bf3a5f08fa81", 1496400309, 0x1a64bc7a, "", "", "000000000000000000000000000000000000000000000003445c0d4e9d2e2049"),
    Checkpoint::new(700000, "00000000000002958852d255726d695ecccfbfacfac318a9d0ebc558eecefeb9", 1499552504, 0x1a37e005, "", "", "0000000000000000000000000000000000000000000000043fa186270b24e45e"),
    Checkpoint::new(720000, "0000000000000acfc49b67e8e72c6faa2d057720d13b9052161305654b39b281", 1502702260, 0x1a158e98, "", "", "000000000000000000000000000000000000000000000006805f0f3d9f8a7187"),
    Checkpoint::new(740000, "00000000000008d0d8a9054072b0272024a01d1920ab4d5a5eb98584930cbd4c", 1505852282, 0x1a0ab756, "", "", "00000000000000000000000000000000000000000000000bba02927a1eacc86f"),
    Checkpoint::new(760000, "000000000000011131c4a8c6446e6ce4597a192296ecad0fb47a23ae4b506682", 1508998683, 0x1a014ed1, "", "", "00000000000000000000000000000000000000000000002cb42ee0f60ddb3d9b"),
    Checkpoint::new(780000, "0000000000000019c30fd5b13548fe169068cbcedb1efb14a630398c26a0ae3b", 1512146289, 0x19408279, "", "", "0000000000000000000000000000000000000000000000d80f87019d91a7e5b3"),
    Checkpoint::new(800000, "000000000000002a702916db91213077926866437a6b63e90548af03647d5df3", 1515298907, 0x193a412a, "", "", "00000000000000000000000000000000000000000000024db269cc7723ab75d2"),
    Checkpoint::new(820000, "0000000000000006619ae1f0fc453690183f571817ef677a822b76d133ea920b", 1518449736, 0x192ab829, "", "", "0000000000000000000000000000000000000000000003aa4d4c30ea62280b01"),
    Checkpoint::new(840000, "000000000000000dfb1273aad00884845ddbde6371f44f3fe1a157d057e7757e", 1521602534, 0x194d5e8e, "", "", "000000000000000000000000000000000000000000000528408f8f46572a4ede"),
    Checkpoint::new(860000, "000000000000001ed76fb953e7e96daf7000f657594a909540b0da6aa2252393", 1524751102, 0x1933df60, "", "", "000000000000000000000000000000000000000000000662e04603d45ee888c2"),
    Checkpoint::new(880000, "000000000000001c980f140d5ff954581b0b35d680e03f4aeba30505cb1072a6", 1527903835, 0x1962d4ed, "", "", "000000000000000000000000000000000000000000000791b70924e953c256ef"),
    Checkpoint::new(900000, "000000000000001eedab948c433a50b1131a8e15c8c2beef4be237701feff7b5", 1531055382, 0x1945cebc, "", "", "0000000000000000000000000000000000000000000008a8ae840f52917fa49d"),
    Checkpoint::new(920000, "00000000000000341469d7ab5aa190cbf49a19ac69afcf8cfd608d7f8cdf7245", 1534206756, 0x1950c940, "", "", "0000000000000000000000000000000000000000000009b77333a84f2528943d"),
    Checkpoint::new(940000, "000000000000001232b541264361386c0ea40ac3f0b72814b48a16a249c5386c", 1537357320, 0x1952e364, "", "", "000000000000000000000000000000000000000000000ac9399559fe5c2c4495"),
    Checkpoint::new(960000, "000000000000004a74127b49e7eebbde24253f08677880b4d0fd20c5637ab68c", 1540510859, 0x1965c6b0, "", "", "000000000000000000000000000000000000000000000c16096182b08f8ce451"),
    Checkpoint::new(980000, "0000000000000014a649707045782b2fa540492865a253d8beec12de1c69d513", 1543661716, 0x1935793a, "", "", "000000000000000000000000000000000000000000000de16f70813f98add8de"),
    Checkpoint::new(1000000, "000000000000000c9167ee9675411440e10e9adbc21fb57b88879fc293e9d494", 1546810296, 0x194a441c, "", "", "000000000000000000000000000000000000000000000f06009e8ebc22f41596"),
    Checkpoint::new(1020000, "000000000000000ec0df78766bfe87f2414177c64a3960dc0ab06351ba81881e", 1549961482, 0x19469e2a, "", "", "0000000000000000000000000000000000000000000010442011fac56db44009"),
    Checkpoint::new(1040000, "0000000000000014ddf198355bf1e10dd848465b0296097a520619c73f87e11a", 1553111735, 0x1934898b, "", "", "0000000000000000000000000000000000000000000011b50754cb72e8a662bf"),
    Checkpoint::new(1060000, "00000000000000132447e6bac9fe0d7d756851450eab29358787dc05d809bf07", 1556260812, 0x191f6ace, "", "", "000000000000000000000000000000000000000000001392c164c11ca344daec"),
    Checkpoint::new(1080000, "00000000000000099c5cc38bac7878f771408537e520a1ef9e31b5c1040d2d2a", 1559412342, 0x192a9588, "", "", "0000000000000000000000000000000000000000000015a7e09c202c817e33d8"),
    Checkpoint::new(1088640, "00000000000000112e41e4b3afda8b233b8cc07c532d2eac5de097b68358c43e", 1560773201, 0x1922ae0b, "ML1088640", "379fd491044a273372a8e901866fbe6ed9bab7ce2de0968a71d38de5d5eac340", "0000000000000000000000000000000000000000000016a12b2d3216341ba998"),
    Checkpoint::new(1100000, "00000000000000190560ed4b128c156e489fdbe0814bf62c8ab53ab3259d7908", 1562561033, 0x191a9f05, "", "", "0000000000000000000000000000000000000000000017ffbd499dd0911202a4"),
    Checkpoint::new(1120000, "0000000000000011103eae768e6a322b991c5c20569d95930b87e1305fa19c75", 1565712301, 0x19200768, "", "", "000000000000000000000000000000000000000000001a7cca810db5e54e95ca"),
    Checkpoint::new(1140000, "00000000000000083ac0e592e180487cb237f659a305d2be19e883ed564fe20f", 1568864488, 0x1923198b, "", "", "000000000000000000000000000000000000000000001ccf1b2b6718aad9bb8d"),
    Checkpoint::new(1160000, "00000000000000098f985e79ca74ca2cf8c113763f8184011759306945149309", 1572017931, 0x191f3f6e, "", "", "000000000000000000000000000000000000000000001f9c55ec0edb976f5b91"),
    Checkpoint::new(1180000, "0000000000000001e1de4be8cafd6b0dc70a16293f8e82bcc41a87d80032ac34", 1575169584, 0x191bb2a5, "", "", "0000000000000000000000000000000000000000000022627cdba7173758a936"),
    Checkpoint::new(1200000, "0000000000000005fbc6c64e048be7c29d43e4829f360220cededb73ce84894c", 1578321180, 0x191c82aa, "", "", "0000000000000000000000000000000000000000000025480b80cfaaa03cb202"),
    Checkpoint::new(1220000, "00000000000000088d62064bf4fde648fe8d573dc93ef38434e81cfe612de78c", 1581472545, 0x190f1e55, "", "", "000000000000000000000000000000000000000000002892bc088c580f189ec0"),
    Checkpoint::new(1240000, "000000000000000aa3928f6e2a96284f8540b79af896a5d6c1fec2a942757014", 1584625095, 0x1916f846, "", "", "000000000000000000000000000000000000000000002be2d3460847285e4525"),
    Checkpoint::new(1260000, "0000000000000014248d9dd7bf974be79934c6907c7ecdd17b7117fb32471254", 1587777968, 0x19196cf5, "", "", "000000000000000000000000000000000000000000002f070e3cafbdd9c6ae29"),
    Checkpoint::new(1280000, "000000000000000f645b651d74ef4c3c32c4cfccb57f0b0d8cf8c74bb28657c9", 1590930959, 0x191566f1, "", "", "0000000000000000000000000000000000000000000032be4046d20f36f17533"),
    Checkpoint::new(1300000, "00000000000000089645b1efe2dd9220972f98221b2bb6a4b9126995ad2b211f", 1594082464, 0x191310ba, "", "", "0000000000000000000000000000000000000000000036bfd2be720d00beef7f"),
    Checkpoint::new(1320000, "00000000000000085c6851916fca710b38b61a8d29007cebe0cdd3e9532fb41a", 1597235050, 0x191832f7, "", "", "000000000000000000000000000000000000000000003b2ae734f23f675326b8"),
    Checkpoint::new(1340000, "000000000000000dd95cf5a7f68f227351b9de2d6876aa05de661d9b3e7408c2", 1600387053, 0x19106cfa, "", "", "000000000000000000000000000000000000000000003f8520378bb8baa9b658"),
    Checkpoint::new(1360000, "000000000000000fbc053861445cc9efdbcb86c293e39f3e474d0692362f4d31", 1603539366, 0x19124c76, "", "", "0000000000000000000000000000000000000000000043ff52430c7d90bdb5b8"),
    Checkpoint::new(1400000, "0000000000000009cb41f7c4e584ecd9a8b4fbc56f68948471104b75b2685085", 1609844689, 0x190d3fbf, "", "", "000000000000000000000000000000000000000000004be2a51a9acad8da4201"),
    Checkpoint::new(1420000, "0000000000000009c6f8c45f81285d81ff3bb6ba0e60edddcfeb6575233f08e5", 1612995382, 0x1918c895, "", "", "000000000000000000000000000000000000000000004f4e6346d3343f17a19d"),
    Checkpoint::new(1440000, "0000000000000010de78b6bfcf66a3a4e41b94d12a26d5738b8695e06a89a910", 1616147964, 0x19291041, "", "", "0000000000000000000000000000000000000000000052cdd78e3c14840708c9"),
    Checkpoint::new(1460000, "00000000000000009891170e922835b046a48dcb738f6c2287f144ad7d65c249", 1619299133, 0x1917b640, "", "", "00000000000000000000000000000000000000000000564b000497f415361b49"),
    Checkpoint::new(1480000, "000000000000000f77a58a12db0814ca0602e476a9c033d5163ad0be79f368e1", 1622453027, 0x19198712, "", "", "0000000000000000000000000000000000000000000059bb58cda63f2a65978e"),
    Checkpoint::new(1500000, "0000000000000002cb2f0d030e9744cd6d93b913b80958b232e4f0b84d828ecf", 1625606293, 0x192fa83e, "", "a1302fd89ad90284ec2282f058018e7f567e731851a523987b8fd49437839a5c", "000000000000000000000000000000000000000000005cc3c1ba9c4e8e7b2a9c"),
    Checkpoint::new(1520000, "000000000000000e21e9ac8dcc9dc104b8ff338e0001570f80cf8d5fe9df32dd", 1628758467, 0x19270200, "", "0f3725a044bd40ede44c1c8ba97860dd749fee0b150028e5bc015eae4aaa9e98", "000000000000000000000000000000000000000000005f09c125e8c3e7bcd353"),
    Checkpoint::new(1540000, "00000000000000106894f49f5a0717033a68d59c9558e6ef6c9f376b4db28ce1", 1631912253, 0x191c49a8, "", "ad141a4fb8d41cd25fa4b5e9b914932adec9e7668688061354f274dc599a8aaf", "0000000000000000000000000000000000000000000061e16a8964a975ea7c48"),
    Checkpoint::new(1560000, "000000000000000633416a01f715a79fe6d4b9aa06a71c5268444e0e614462e6", 1635065427, 0x191ba389, "", "7567b3c5d438358a86a639d33caaebac01e9cc7e26f90fbf74e32d5d707777d8", "000000000000000000000000000000000000000000006418e34f25808971f8a1"),
    Checkpoint::new(1580000, "0000000000000011cef69161b9fefee81d90114ea888df085fe6d5d1543cb82c", 1638219545, 0x1927806d, "", "f2d54ed7a987ef18c6ba9fc6af6d894e3891725813458831c666e2c369690625", "00000000000000000000000000000000000000000000661ebb8722e8110ee1f5"),
    Checkpoint::new(1600000, "000000000000000dd58a1fc9f4447e1737a2c840545ece749f1a6847757468a5", 1641372443, 0x191a9cb3, "", "517be14dd017698bbaaa07a4e03335efb551266780d1e3109b1233283b73c4ad", "0000000000000000000000000000000000000000000068bc95c8ef608051870c"),
    Checkpoint::new(1620000, "000000000000000c2cb8178d7e3d7bb8b1eef5390eb0af5c9a9186c5da5b10f9", 1644527681, 0x1920ed2b, "", "8b866e36bf0c39fa11f7884ee8a86263392022dbd54f4f497f3cc2ab3eba4979", "000000000000000000000000000000000000000000006b874f059550b9404573"),
    Checkpoint::new(1640000, "0000000000000000d33ab243b89793092ae2776553481d6087323cc03ae6bd3a", 1647680698, 0x1915d5e9, "", "5912b841d5677708519c8ea1216c9df514a863bb69cc7c76149db140e8686d52", "000000000000000000000000000000000000000000006e45f1051e71cdd49896"),
    Checkpoint::new(1660000, "000000000000001b20b333c002a601c08886f43ebbe7ca5313ea3bf50e822a4a", 1650834999, 0x19281301, "", "16a98a58107c9a54bc74961e68de13eabac4f13933c66251377fe6552c020257", "0000000000000000000000000000000000000000000070fa4acdb1bfaf830f2a"),
    Checkpoint::new(1680000, "000000000000001d4107019248ea733abc4fd02b31db202f6bfd38f8848c7100", 1653989911, 0x192af7ed, "", "dd516ade3a5b599a6989a36e137be9e14f0fd77dad036c6c0748bfbbd73d9805", "0000000000000000000000000000000000000000000073575a368d41c4d9641c"),
    Checkpoint::new(1700000, "000000000000001d7579a371e782fd9c4480f626a62b916fa4eb97e16a49043a", 1657142113, 0x1927e30e, "", "dafe57cefc3bc265dfe8416e2f2e3a22af268fd587a48f36affd404bec738305", "000000000000000000000000000000000000000000007562df93a26b81386288"),
    Checkpoint::new(1720000, "000000000000001ef1f8a3d33bbe304c1d12f59f2c8aa989099dc215fd10903e", 1660295895, 0x19362176, "ML1720000", "67c6348c35bc42aa4cabd25e29560f5d22c6a9fba274bf0c52fe73021d0e8d5e", "000000000000000000000000000000000000000000007715a9ae4dd7ff1d3902"),

];
