pub struct Environment {

}
impl Environment {
    pub fn new() -> Self {
        Self {

        }
    }
    // true if this is a "watch only" wallet with no signing ability
    pub fn watch_only() -> bool {
        Chainsm
        for  in  {

        }
    }
    - (BOOL)watchOnly {
    static BOOL watchOnly;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
    @autoreleasepool {
    for (DSChain *chain in [[DSChainsManager sharedInstance] chains]) {
    for (DSWallet *wallet in [chain wallets]) {
    DSAccount *account = [wallet accountWithNumber:0];
    NSString *keyString = [[account bip44DerivationPath] walletBasedExtendedPublicKeyLocationString];
    NSError *error = nil;
    NSData *v2BIP44Data = getKeychainData(keyString, &error);

    watchOnly = (v2BIP44Data && v2BIP44Data.length == 0) ? YES : NO;
    }
    }
    }
    });

    return watchOnly;
}

}
