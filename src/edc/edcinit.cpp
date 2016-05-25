// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcinit.h"
#include "edcparams.h"
#include "edc/wallet/edcwallet.h"
#include "util.h"
#include "utilmoneystr.h"
#include "edcchainparams.h"



bool EdcAppInit(
	boost::thread_group & threadGroup, 
		 	 CScheduler & scheduler)
{

	return true;
}

#if 0
    try
    {
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        try {
            SelectParams(ChainNameFromCommandLine());
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // Command-line RPC
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "bitcoin:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            fprintf(stderr, "Error: There is no RPC client functionality in bitcoind anymore. Use the bitcoin-cli utility instead.\n");
            exit(1);
        }
#ifndef WIN32
        fDaemon = GetBoolArg("-daemon", false);
        if (fDaemon)
        {
            fprintf(stdout, "Bitcoin server starting\n");

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true);

        // Set this early so that parameter interactions go to console
        InitLogging();
        InitParameterInteraction();
        fRet = AppInit2(threadGroup, scheduler);
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
    // which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    if (!SetupNetworking())
        return InitError("Initializing networking failed");

#ifndef WIN32
    if (GetBoolArg("-sysperms", false)) {
#ifdef ENABLE_WALLET
        if (!GetBoolArg("-disablewallet", false))
            return InitError("-sysperms is not allowed in combination with enabled wallet functionality");
#endif
    } else {
        umask(077);
    }

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#endif

    // ********************************************************* Step 2: parameter interactions
    const CChainParams& chainparams = Params();

    // also see: InitParameterInteraction()

    // if using block pruning, then disable txindex
    if (GetArg("-prune", 0)) {
        if (GetBoolArg("-txindex", EDC_DEFAULT_TXINDEX))
            return InitError(_("Prune mode is incompatible with -txindex."));
#ifdef ENABLE_WALLET
        if (GetBoolArg("-rescan", false)) {
            return InitError(_("Rescans are not possible in pruned mode. You will need to use -reindex which will download the whole blockchain again."));
        }
#endif
    }

    // Make sure enough file descriptors are available
    int nBind = std::max((int)mapArgs.count("-bind") + (int)mapArgs.count("-whitebind"), 1);
    int nUserMaxConnections = GetArg("-maxconnections", EDC_DEFAULT_MAX_PEER_CONNECTIONS);
    nMaxConnections = std::max(nUserMaxConnections, 0);

    // Trim requested connection counts, to fit into system limitations
    nMaxConnections = std::max(std::min(nMaxConnections, (int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0);
    int nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
        return InitError(_("Not enough file descriptors available."));
    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS, nMaxConnections);

    if (nMaxConnections < nUserMaxConnections)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), nUserMaxConnections, nMaxConnections));

    // ********************************************************* Step 3: parameter-to-internal-flags

    fDebug = !mapMultiArgs["-debug"].empty();
    // Special-case: if -debug=0/-nodebug is set, turn off debugging messages
    const vector<std::string>& categories = mapMultiArgs["-debug"];
    if (GetBoolArg("-nodebug", false) || find(categories.begin(), categories.end(), std::string("0")) != categories.end())
        fDebug = false;

    // Check for -debugnet
    if (GetBoolArg("-debugnet", false))
        InitWarning(_("Unsupported argument -debugnet ignored, use -debug=net."));
    // Check for -socks - as this is a privacy risk to continue, exit here
    if (mapArgs.count("-socks"))
        return InitError(_("Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));
    // Check for -tor - as this is a privacy risk to continue, exit here
    if (GetBoolArg("-tor", false))
        return InitError(_("Unsupported argument -tor found, use -onion."));

    if (GetBoolArg("-benchmark", false))
        InitWarning(_("Unsupported argument -benchmark ignored, use -debug=bench."));

    if (GetBoolArg("-whitelistalwaysrelay", false))
        InitWarning(_("Unsupported argument -whitelistalwaysrelay ignored, use -whitelistrelay and/or -whitelistforcerelay."));

    // Checkmempool and checkblockindex default to true in regtest mode
    int ratio = std::min<int>(std::max<int>(GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0), 1000000);
    if (ratio != 0) {
        mempool.setSanityCheck(1.0 / ratio);
    }
    fCheckBlockIndex = GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks());
    fCheckpointsEnabled = GetBoolArg("-checkpoints", EDC_DEFAULT_CHECKPOINTS_ENABLED);

    // mempool limits
    int64_t nMempoolSizeMax = GetArg("-maxmempool", EDC_DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    int64_t nMempoolSizeMin = GetArg("-limitdescendantsize", EDC_DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency
    nScriptCheckThreads = GetArg("-par", EDC_DEFAULT_SCRIPTCHECK_THREADS);
    if (nScriptCheckThreads <= 0)
        nScriptCheckThreads += GetNumCores();
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS;

    fServer = GetBoolArg("-server", false);

    // block pruning; get the amount of disk space (in MiB) to allot for block & undo files
    int64_t nSignedPruneTarget = GetArg("-prune", 0) * 1024 * 1024;
    if (nSignedPruneTarget < 0) {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t) nSignedPruneTarget;
    if (nPruneTarget) {
        if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) {
            return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        LogPrintf("Prune configured to target %uMiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

    RegisterAllCoreRPCCommands(tableRPC);
#ifdef ENABLE_WALLET
    bool fDisableWallet = GetBoolArg("-disablewallet", false);
    if (!fDisableWallet)
        RegisterWalletRPCCommands(tableRPC);
#endif

    nConnectTimeout = GetArg("-timeout", EDC_DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0)
        nConnectTimeout = EDC_DEFAULT_CONNECT_TIMEOUT;

    // Fee-per-kilobyte amount considered the same as "free"
    // If you are mining, be careful setting this:
    // if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    if (mapArgs.count("-minrelaytxfee"))
    {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-minrelaytxfee"], n) && n > 0)
            ::minRelayTxFee = CFeeRate(n);
        else
            return InitError(AmountErrMsg("minrelaytxfee", mapArgs["-minrelaytxfee"]));
    }

    fRequireStandard = !GetBoolArg("-acceptnonstdtxn", !Params().RequireStandard());
    if (Params().RequireStandard() && !fRequireStandard)
        return InitError(strprintf("acceptnonstdtxn is not currently supported for %s chain", chainparams.NetworkIDString()));
    nBytesPerSigOp = GetArg("-bytespersigop", nBytesPerSigOp);

#ifdef ENABLE_WALLET
    if (!CWallet::ParameterInteraction())
        return false;
#endif // ENABLE_WALLET

    fIsBareMultisigStd = GetBoolArg("-permitbaremultisig", EDC_DEFAULT_PERMIT_BAREMULTISIG);
    fAcceptDatacarrier = GetBoolArg("-datacarrier", EDC_DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op

    if (GetBoolArg("-peerbloomfilters", EDC_DEFAULT_PEERBLOOMFILTERS))
        nLocalServices |= NODE_BLOOM;

    nMaxTipAge = GetArg("-maxtipage", EDC_DEFAULT_MAX_TIP_AGE);

    fEnableReplacement = GetBoolArg("-mempoolreplacement", EDC_DEFAULT_ENABLE_REPLACEMENT);
    if ((!fEnableReplacement) && mapArgs.count("-mempoolreplacement")) {
        // Minimal effort at forwards compatibility
        std::string strReplacementModeList = GetArg("-mempoolreplacement", "");  // default is impossible
        std::vector<std::string> vstrReplacementModes;
        boost::split(vstrReplacementModes, strReplacementModeList, boost::is_any_of(","));
        fEnableReplacement = (std::find(vstrReplacementModes.begin(), vstrReplacementModes.end(), "fee") != vstrReplacementModes.end());
    }

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    // Initialize elliptic curve code
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), _(PACKAGE_NAME)));

    std::string strDataDir = GetDataDir().string();

    // Make sure only a single Bitcoin process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);

    try {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
        if (!lock.try_lock())
            return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."), strDataDir, _(PACKAGE_NAME)));
    } catch(const boost::interprocess::interprocess_exception& e) {
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running.") + " %s.", strDataDir, _(PACKAGE_NAME), e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid());
#endif
    if (GetBoolArg("-shrinkdebugfile", !fDebug))
        ShrinkDebugFile();

    if (fPrintToDebugLog)
        OpenDebugLog();

    if (!fLogTimestamps)
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string());
    LogPrintf("Using data directory %s\n", strDataDir);
    LogPrintf("Using config file %s\n", GetConfigFile().string());
    LogPrintf("Using at most %i connections (%i file descriptors available)\n", nMaxConnections, nFD);
    std::ostringstream strErrors;

    LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads);
    if (nScriptCheckThreads) {
        for (int i=0; i<nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
    }

    // Start the lightweight task scheduler thread
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler);
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop));

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (fServer)
    {
        uiInterface.InitMessage.connect(SetRPCWarmupStatus);
        if (!AppInitServers(threadGroup))
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    int64_t nStart;

    // ********************************************************* Step 5: verify wallet database integrity
#ifdef ENABLE_WALLET
    if (!fDisableWallet) {
        if (!CWallet::Verify())
            return false;
    } // (!fDisableWallet)
#endif // ENABLE_WALLET
    // ********************************************************* Step 6: network initialization

    RegisterNodeSignals(GetNodeSignals());

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<std::string> uacomments;
    BOOST_FOREACH(std::string cmt, mapMultiArgs["-uacomment"])
    {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (mapArgs.count("-onlynet")) {
        std::set<enum Network> nets;
        BOOST_FOREACH(const std::string& snet, mapMultiArgs["-onlynet"]) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

    if (mapArgs.count("-whitelist")) {
        BOOST_FOREACH(const std::string& net, mapMultiArgs["-whitelist"]) {
            CSubNet subnet(net);
            if (!subnet.IsValid())
                return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
            CNode::AddWhitelistedRange(subnet);
        }
    }

    bool proxyRandomize = GetBoolArg("-proxyrandomize", EDC_DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = GetArg("-proxy", "");
    SetLimited(NET_TOR);
    if (proxyArg != "" && proxyArg != "0") {
        proxyType addrProxy = proxyType(CService(proxyArg, 9050), proxyRandomize);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_TOR, addrProxy);
        SetNameProxy(addrProxy);
        SetLimited(NET_TOR, false); // by default, -proxy sets onion as reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = GetArg("-onion", "");
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0
            SetLimited(NET_TOR); // set onions as unreachable
        } else {
            proxyType addrOnion = proxyType(CService(onionArg, 9050), proxyRandomize);
            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -onion address: '%s'"), onionArg));
            SetProxy(NET_TOR, addrOnion);
            SetLimited(NET_TOR, false);
        }
    }

    // see Step 2: parameter interactions for more information about these
    fListen = GetBoolArg("-listen", EDC_DEFAULT_LISTEN);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", EDC_DEFAULT_NAME_LOOKUP);

    bool fBound = false;
    if (fListen) {
        if (mapArgs.count("-bind") || mapArgs.count("-whitebind")) {
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-bind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                    return InitError(ResolveErrMsg("bind", strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
            }
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-whitebind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return InitError(ResolveErrMsg("whitebind", strBind));
                if (addrBind.GetPort() == 0)
                    return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
            }
        }
        else {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
            fBound |= Bind(CService(in6addr_any, GetListenPort()), BF_NONE);
            fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE);
        }
        if (!fBound)
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (mapArgs.count("-externalip")) {
        BOOST_FOREACH(const std::string& strAddr, mapMultiArgs["-externalip"]) {
            CService addrLocal;
            if (Lookup(strAddr.c_str(), addrLocal, GetListenPort(), fNameLookup) && addrLocal.IsValid())
                AddLocal(addrLocal, LOCAL_MANUAL);
            else
                return InitError(ResolveErrMsg("externalip", strAddr));
        }
    }

    BOOST_FOREACH(const std::string& strDest, mapMultiArgs["-seednode"])
        AddOneShot(strDest);

#if ENABLE_ZMQ
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs);

    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif
    if (mapArgs.count("-maxuploadtarget")) {
        CNode::SetMaxOutboundTarget(GetArg("-maxuploadtarget", EDC_DEFAULT_MAX_UPLOAD_TARGET)*1024*1024);
    }

    // ********************************************************* Step 7: load block chain

    fReindex = GetBoolArg("-reindex", false);

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
    boost::filesystem::path blocksDir = GetDataDir() / "blocks";
    if (!boost::filesystem::exists(blocksDir))
    {
        boost::filesystem::create_directories(blocksDir);
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++) {
            boost::filesystem::path source = GetDataDir() / strprintf("blk%04u.dat", i);
            if (!boost::filesystem::exists(source)) break;
            boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i-1);
            try {
                boost::filesystem::create_hard_link(source, dest);
                LogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true;
            } catch (const boost::filesystem::filesystem_error& e) {
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                LogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                break;
            }
        }
        if (linked)
        {
            fReindex = true;
        }
    }

    // cache size calculations
    int64_t nTotalCache = (GetArg("-dbcache", EDC_DEFAULT_DB_CACHE) << 20);
    nTotalCache = std::max(nTotalCache, EDC_MIN_DB_CACHE << 20); // total cache cannot be less than EDC_MIN_DB_CACHE
    nTotalCache = std::min(nTotalCache, EDC_MAX_DB_CACHE << 20); // total cache cannot be greated than EDC_MAX_DB_CACHE
    int64_t nBlockTreeDBCache = nTotalCache / 8;
    if (nBlockTreeDBCache > (1 << 21) && !GetBoolArg("-txindex", EDC_DEFAULT_TXINDEX))
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache
    nTotalCache -= nCoinDBCache;
    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

    bool fLoaded = false;
    while (!fLoaded) {
        bool fReset = fReindex;
        std::string strLoadError;

        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do {
            try {
                UnloadBlockIndex();
                delete pcoinsTip;
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete pblocktree;

                pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex);
                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, fReindex);
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);

                if (fReindex) {
                    pblocktree->WriteReindexing(true);
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (fPruneMode)
                        CleanupBlockRevFiles();
                }

                if (!LoadBlockIndex()) {
                    strLoadError = _("Error loading block database");
                    break;
                }

                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!InitBlockIndex(chainparams)) {
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // Check for changed -txindex state
                if (fTxIndex != GetBoolArg("-txindex", EDC_DEFAULT_TXINDEX)) {
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.
                if (fHavePruned && !fPruneMode) {
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                uiInterface.InitMessage(_("Verifying blocks..."));
                if (fHavePruned && GetArg("-checkblocks", EDC_DEFAULT_CHECKBLOCKS) > MIN_BLOCKS_TO_KEEP) {
                    LogPrintf("Prune: pruned datadir may not have more than %d blocks; -checkblocks=%d may fail\n",
                        MIN_BLOCKS_TO_KEEP, GetArg("-checkblocks", EDC_DEFAULT_CHECKBLOCKS));
                }

                {
                    LOCK(cs_main);
                    CBlockIndex* tip = chainActive.Tip();
                    if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60) {
                        strLoadError = _("The block database contains a block which appears to be from the future. "
                                "This may be due to your computer's date and time being set incorrectly. "
                                "Only rebuild the block database if you are sure that your computer's date and time are correct");
                        break;
                    }
                }

                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview, GetArg("-checklevel", EDC_DEFAULT_CHECKLEVEL),
                              GetArg("-checkblocks", EDC_DEFAULT_CHECKBLOCKS))) {
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
            } catch (const std::exception& e) {
                if (fDebug) LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while(false);

        if (!fLoaded) {
            // first suggest a reindex
            if (!fReset) {
                bool fRet = uiInterface.ThreadSafeMessageBox(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"),
                    "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet) {
                    fReindex = true;
                    fRequestShutdown = false;
                } else {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return InitError(strLoadError);
            }
        }
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    LogPrintf(" block index %15dms\n", GetTimeMillis() - nStart);

    boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.
    if (!est_filein.IsNull())
        mempool.ReadFeeEstimates(est_filein);
    fFeeEstimatesInitialized = true;

    // ********************************************************* Step 8: load wallet
#ifdef ENABLE_WALLET
    if (fDisableWallet) {
        pwalletMain = NULL;
        LogPrintf("Wallet disabled!\n");
    } else {
        CWallet::InitLoadWallet();
        if (!pwalletMain)
            return false;
    }
#else // ENABLE_WALLET
    LogPrintf("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

    // ********************************************************* Step 9: data directory maintenance

    // if pruning, unset the service bit and perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (fPruneMode) {
        LogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        nLocalServices &= ~NODE_NETWORK;
        if (!fReindex) {
            uiInterface.InitMessage(_("Pruning blockstore..."));
            PruneAndFlush();
        }
    }

    // ********************************************************* Step 10: import blocks

    if (mapArgs.count("-blocknotify"))
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback);

    uiInterface.InitMessage(_("Activating best chain..."));
    // scan for better chains in the block chain database, that are not yet connected in the active best chain
    CValidationState state;
    if (!ActivateBestChain(state, chainparams))
        strErrors << "Failed to connect best block";

    std::vector<boost::filesystem::path> vImportFiles;
    if (mapArgs.count("-loadblock"))
    {
        BOOST_FOREACH(const std::string& strFile, mapMultiArgs["-loadblock"])
            vImportFiles.push_back(strFile);
    }
    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles));
    if (chainActive.Tip() == NULL) {
        LogPrintf("Waiting for genesis block to be imported...\n");
        while (!fRequestShutdown && chainActive.Tip() == NULL)
            MilliSleep(10);
    }

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())
        return false;

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    RandAddSeedPerfmon();

    //// debug print
    LogPrintf("mapBlockIndex.size() = %u\n",   mapBlockIndex.size());
    LogPrintf("nBestHeight = %d\n",                   chainActive.Height());
#ifdef ENABLE_WALLET
    LogPrintf("setKeyPool.size() = %u\n",      pwalletMain ? pwalletMain->setKeyPool.size() : 0);
    LogPrintf("mapWallet.size() = %u\n",       pwalletMain ? pwalletMain->mapWallet.size() : 0);
    LogPrintf("mapAddressBook.size() = %u\n",  pwalletMain ? pwalletMain->mapAddressBook.size() : 0);
#endif

    if (GetBoolArg("-listenonion", EDC_DEFAULT_LISTEN_ONION))
        StartTorControl(threadGroup, scheduler);

    StartNode(threadGroup, scheduler);

    // Monitor the chain, and alert if we get blocks much quicker or slower than expected
    int64_t nPowTargetSpacing = Params().GetConsensus().nPowTargetSpacing;
    CScheduler::Function f = boost::bind(&PartitionCheck, &IsInitialBlockDownload,
                                         boost::ref(cs_main), boost::cref(pindexBestHeader), nPowTargetSpacing);
    scheduler.scheduleEvery(f, nPowTargetSpacing);

    // ********************************************************* Step 12: finished

    SetRPCWarmupFinished();
    uiInterface.InitMessage(_("Done loading"));

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions();

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile)));
    }
#endif

    return !fRequestShutdown;
}
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    return fRet;
}

#endif

std::string edcHelpMessage(HelpMessageMode mode)
{
    const bool showDebug = GetBoolArg("-help-debug", false);

	////////////////////////////////////////////////////////////////////////
    std::string strUsage = HelpMessageGroup(_("Equibit Options:"));

    strUsage += HelpMessageOpt("-ebalertnotify=<cmd>", 
		_("Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)"));
    strUsage += HelpMessageOpt("-ebblocknotify=<cmd>", 
		_("Execute command when the best block changes (%s in cmd is replaced by block hash)"));

    if (showDebug)
        strUsage += HelpMessageOpt("-ebblocksonly", 
			strprintf(_("Whether to operate in a blocks only mode (default: %u)"), EDC_DEFAULT_BLOCKSONLY));
    strUsage += HelpMessageOpt("-ebcheckblocks=<n>", 
		strprintf(_("How many blocks to check at startup (default: %u, 0 = all)"), EDC_DEFAULT_CHECKBLOCKS));
    strUsage += HelpMessageOpt("-ebchecklevel=<n>", 
		strprintf(_("How thorough the block verification of -checkblocks is (0-4, default: %u)"), EDC_DEFAULT_CHECKLEVEL));
    strUsage += HelpMessageOpt("-ebconf=<file>", 
		strprintf(_("Specify configuration file (default: %s)"), BITCOIN_CONF_FILENAME));
    strUsage += HelpMessageOpt("-ebdatadir=<dir>", 
		_("Specify data directory"));
    strUsage += HelpMessageOpt("-ebdbcache=<n>", 
		strprintf(_("Set database cache size in megabytes (%d to %d, default: %d)"), EDC_MIN_DB_CACHE, EDC_MAX_DB_CACHE, EDC_DEFAULT_DB_CACHE));
    strUsage += HelpMessageOpt("-ebfeefilter", 
		strprintf(_("Tell other nodes to filter invs to us by our mempool min fee (default: %u)"), EDC_DEFAULT_FEEFILTER));
    strUsage += HelpMessageOpt("-ebloadblock=<file>", 
		_("Imports blocks from external blk000??.dat file on startup"));
    strUsage += HelpMessageOpt("-ebmaxorphantx=<n>", 
		strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), EDC_DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-ebmaxmempool=<n>", 
		strprintf(_("Keep the transaction memory pool below <n> megabytes (default: %u)"), EDC_DEFAULT_MAX_MEMPOOL_SIZE));
    strUsage += HelpMessageOpt("-ebmempoolexpiry=<n>", 
		strprintf(_("Do not keep transactions in the mempool longer than <n> hours (default: %u)"), EDC_DEFAULT_MEMPOOL_EXPIRY));
    strUsage += HelpMessageOpt("-ebpar=<n>", 
		strprintf(_("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)"),
        -GetNumCores(), EDC_MAX_SCRIPTCHECK_THREADS, EDC_DEFAULT_SCRIPTCHECK_THREADS));
#ifndef WIN32
    strUsage += HelpMessageOpt("-ebpid=<file>", 
		strprintf(_("Specify pid file (default: %s)"), BITCOIN_PID_FILENAME));
#endif
    strUsage += HelpMessageOpt("-ebprune=<n>", 
		strprintf(_("Reduce storage requirements by pruning (deleting) old blocks. This mode is incompatible with -txindex and -rescan. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, >%u = target size in MiB to use for block files)"), EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
    strUsage += HelpMessageOpt("-ebreindex", 
		_("Rebuild block chain index from current blk000??.dat files on startup"));
    strUsage += HelpMessageOpt("-ebtxindex", 
		strprintf(_("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)"), EDC_DEFAULT_TXINDEX));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Connection options:"));

    strUsage += HelpMessageOpt("-ebaddnode=<ip>", 
		_("Add a node to connect to and attempt to keep the connection open"));
    strUsage += HelpMessageOpt("-ebbanscore=<n>", 
		strprintf(_("Threshold for disconnecting misbehaving peers (default: %u)"), EDC_DEFAULT_BANSCORE_THRESHOLD));
    strUsage += HelpMessageOpt("-ebbantime=<n>", 
		strprintf(_("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"), EDC_DEFAULT_MISBEHAVING_BANTIME));
    strUsage += HelpMessageOpt("-ebbind=<addr>", 
		_("Bind to given address and always listen on it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-ebconnect=<ip>", 
		_("Connect only to the specified node(s)"));
    strUsage += HelpMessageOpt("-ebdiscover", 
		_("Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)"));
    strUsage += HelpMessageOpt("-ebdns", 
		_("Allow DNS lookups for -addnode, -seednode and -connect") + " " + 
		strprintf(_("(default: %u)"), EDC_DEFAULT_NAME_LOOKUP));
    strUsage += HelpMessageOpt("-ebdnsseed", 
		_("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect)"));
    strUsage += HelpMessageOpt("-ebexternalip=<ip>", 
		_("Specify your own public address"));
    strUsage += HelpMessageOpt("-ebforcednsseed", 
		strprintf(_("Always query for peer addresses via DNS lookup (default: %u)"), EDC_DEFAULT_FORCEDNSSEED));
    strUsage += HelpMessageOpt("-eblisten", 
		_("Accept connections from outside (default: 1 if no -proxy or -connect)"));
    strUsage += HelpMessageOpt("-eblistenonion", 
		strprintf(_("Automatically create Tor hidden service (default: %d)"), EDC_DEFAULT_LISTEN_ONION));
    strUsage += HelpMessageOpt("-ebmaxconnections=<n>", 
		strprintf(_("Maintain at most <n> connections to peers (default: %u)"), EDC_DEFAULT_MAX_PEER_CONNECTIONS));
    strUsage += HelpMessageOpt("-ebmaxreceivebuffer=<n>", 
		strprintf(_("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)"), EDC_DEFAULT_MAXRECEIVEBUFFER));
    strUsage += HelpMessageOpt("-ebmaxsendbuffer=<n>", 
		strprintf(_("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)"), EDC_DEFAULT_MAXSENDBUFFER));
    strUsage += HelpMessageOpt("-ebmaxtimeadjustment", 
		strprintf(_("Maximum allowed median peer time offset adjustment. Local perspective of time may be influenced by peers forward or backward by this amount. (default: %u seconds)"), EDC_DEFAULT_MAX_TIME_ADJUSTMENT));
    strUsage += HelpMessageOpt("-ebonion=<ip:port>", 
		strprintf(_("Use separate SOCKS5 proxy to reach peers via Tor hidden services (default: %s)"), "-proxy"));
    strUsage += HelpMessageOpt("-ebonlynet=<net>", 
		_("Only connect to nodes in network <net> (ipv4, ipv6 or onion)"));
    strUsage += HelpMessageOpt("-ebpermitbaremultisig", 
		strprintf(_("Relay non-P2SH multisig (default: %u)"), EDC_DEFAULT_PERMIT_BAREMULTISIG));
    strUsage += HelpMessageOpt("-ebpeerbloomfilters", 
		strprintf(_("Support filtering of blocks and transaction with bloom filters (default: %u)"), EDC_DEFAULT_PEERBLOOMFILTERS));
    strUsage += HelpMessageOpt("-ebport=<port>", 
		strprintf(_("Listen for connections on <port> (default: %u or testnet: %u)"), Params(CBaseChainParams::MAIN).GetDefaultPort(), Params(CBaseChainParams::TESTNET).GetDefaultPort()));
    strUsage += HelpMessageOpt("-ebproxy=<ip:port>", 
		_("Connect through SOCKS5 proxy"));
    strUsage += HelpMessageOpt("-ebproxyrandomize", 
		strprintf(_("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)"), EDC_DEFAULT_PROXYRANDOMIZE));
    strUsage += HelpMessageOpt("-ebseednode=<ip>", 
		_("Connect to a node to retrieve peer addresses, and disconnect"));
    strUsage += HelpMessageOpt("-ebtimeout=<n>", 
		strprintf(_("Specify connection timeout in milliseconds (minimum: 1, default: %d)"), EDC_DEFAULT_CONNECT_TIMEOUT));
    strUsage += HelpMessageOpt("-ebtorcontrol=<ip>:<port>", 
		strprintf(_("Tor control port to use if onion listening enabled (default: %s)"), EDC_DEFAULT_TOR_CONTROL));
    strUsage += HelpMessageOpt("-ebtorpassword=<pass>", 
		_("Tor control port password (default: empty)"));
#ifdef USE_UPNP
#if USE_UPNP
    strUsage += HelpMessageOpt("-ebupnp", 
		_("Use UPnP to map the listening port (default: 1 when listening and no -proxy)"));
#else
    strUsage += HelpMessageOpt("-ebupnp", 
		strprintf(_("Use UPnP to map the listening port (default: %u)"), 0));
#endif
#endif
    strUsage += HelpMessageOpt("-ebwhitebind=<addr>", 
		_("Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-ebwhitelist=<netmask>", 
		_("Whitelist peers connecting from the given netmask or IP address. Can be specified multiple times.") +
        " " + _("Whitelisted peers cannot be DoS banned and their transactions are always relayed, even if they are already in the mempool, useful e.g. for a gateway"));
    strUsage += HelpMessageOpt("-ebwhitelistrelay", 
		strprintf(_("Accept relayed transactions received from whitelisted peers even when not relaying transactions (default: %d)"), EDC_DEFAULT_WHITELISTRELAY));
    strUsage += HelpMessageOpt("-ebwhitelistforcerelay", 
		strprintf(_("Force relay of transactions from whitelisted peers even they violate local relay policy (default: %d)"), EDC_DEFAULT_WHITELISTFORCERELAY));
    strUsage += HelpMessageOpt("-ebmaxuploadtarget=<n>", 
		strprintf(_("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)"), EDC_DEFAULT_MAX_UPLOAD_TARGET));

#ifdef ENABLE_WALLET
    strUsage += CEDCWallet::GetWalletHelpString(showDebug);
#endif

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Debugging/Testing options:"));

    strUsage += HelpMessageOpt("-ebuacomment=<cmt>", 
		_("Append comment to the user agent string"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-ebcheckblockindex", 
			strprintf("Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and mapBlocksUnlinked occasionally. Also sets -checkmempool (default: %u)", Params(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-ebcheckmempool=<n>", 
			strprintf("Run checks every <n> transactions (default: %u)", Params(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-ebcheckpoints", 
			strprintf("Disable expensive verification for known chain history (default: %u)", EDC_DEFAULT_CHECKPOINTS_ENABLED));
        strUsage += HelpMessageOpt("-ebdisablesafemode", 
			strprintf("Disable safemode, override a real safe mode event (default: %u)", EDC_DEFAULT_DISABLE_SAFEMODE));
        strUsage += HelpMessageOpt("-ebtestsafemode", 
			strprintf("Force safe mode (default: %u)", EDC_DEFAULT_TESTSAFEMODE));
        strUsage += HelpMessageOpt("-ebdropmessagestest=<n>", "Randomly drop 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-ebfuzzmessagestest=<n>", "Randomly fuzz 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-ebstopafterblockimport", 
			strprintf("Stop running after importing blocks from disk (default: %u)", EDC_DEFAULT_STOPAFTERBLOCKIMPORT));
        strUsage += HelpMessageOpt("-eblimitancestorcount=<n>", 
			strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", EDC_DEFAULT_ANCESTOR_LIMIT));
        strUsage += HelpMessageOpt("-eblimitancestorsize=<n>", 
			strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", EDC_DEFAULT_ANCESTOR_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-eblimitdescendantcount=<n>", 
			strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", EDC_DEFAULT_DESCENDANT_LIMIT));
        strUsage += HelpMessageOpt("-eblimitdescendantsize=<n>", 
			strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", EDC_DEFAULT_DESCENDANT_SIZE_LIMIT));
    }
    std::string debugCategories = "addrman, alert, bench, coindb, db, lock, rand, rpc, selectcoins, mempool, mempoolrej, net, proxy, prune, http, libevent, tor, zmq"; // Don't translate these and qt below
    if (mode == HMM_BITCOIN_QT)
        debugCategories += ", qt";
    strUsage += HelpMessageOpt("-ebdebug=<category>", 
		strprintf(_("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
        _("If <category> is not supplied or if <category> = 1, output all debugging information.") + _("<category> can be:") + " " + debugCategories + ".");
    if (showDebug)
        strUsage += HelpMessageOpt("-ebnodebug", "Turn off debugging messages, same as -debug=0");
	strUsage += HelpMessageOpt("-eblogips", 
		strprintf(_("Include IP addresses in debug output (default: %u)"), EDC_DEFAULT_LOGIPS));
    strUsage += HelpMessageOpt("-eblogtimestamps", 
		strprintf(_("Prepend debug output with timestamp (default: %u)"), EDC_DEFAULT_LOGTIMESTAMPS));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-eblogtimemicros", 
			strprintf("Add microsecond precision to debug timestamps (default: %u)", EDC_DEFAULT_LOGTIMEMICROS));
        strUsage += HelpMessageOpt("-eblimitfreerelay=<n>", 
			strprintf("Continuously rate-limit free transactions to <n>*1000 bytes per minute (default: %u)", EDC_DEFAULT_LIMITFREERELAY));
        strUsage += HelpMessageOpt("-ebrelaypriority", 
			strprintf("Require high priority for relaying free or low-fee transactions (default: %u)", EDC_DEFAULT_RELAYPRIORITY));
        strUsage += HelpMessageOpt("-ebmaxsigcachesize=<n>", 
			strprintf("Limit size of signature cache to <n> MiB (default: %u)", EDC_DEFAULT_MAX_SIG_CACHE_SIZE));
        strUsage += HelpMessageOpt("-ebmaxtipage=<n>", 
			strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)", EDC_DEFAULT_MAX_TIP_AGE));
    }
    strUsage += HelpMessageOpt("-ebminrelaytxfee=<amt>", 
		strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)"),
        CURRENCY_UNIT, FormatMoney(EDC_DEFAULT_MIN_RELAY_TX_FEE)));
    strUsage += HelpMessageOpt("-ebmaxtxfee=<amt>", 
		strprintf(_("Maximum total fees (in %s) to use in a single wallet transaction or raw transaction; setting this too low may abort large transactions (default: %s)"),
        CURRENCY_UNIT, FormatMoney(EDC_DEFAULT_TRANSACTION_MAXFEE)));
    strUsage += HelpMessageOpt("-ebprinttoconsole", _("Send trace/debug info to console instead of debug.log file"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-ebprintpriority", 
			strprintf("Log transaction priority and fee per kB when mining blocks (default: %u)", EDC_DEFAULT_PRINTPRIORITY));
    }
    strUsage += HelpMessageOpt("-ebshrinkdebugfile", _("Shrink debug.log file on client startup (default: 1 when no -debug)"));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Chain selection options:"));
    strUsage += HelpMessageOpt("-ebregtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                               "This is intended for regression testing tools and app development.");
    strUsage += HelpMessageOpt("-ebtestnet", _("Use the test chain"));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Node relay options:"));
    if (showDebug)
        strUsage += HelpMessageOpt("-ebacceptnonstdtxn", 
			strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)", "testnet/regtest only; ", !Params(CBaseChainParams::TESTNET).RequireStandard()));
    strUsage += HelpMessageOpt("-ebbytespersigop", 
		strprintf(_("Minimum bytes per sigop in transactions we relay and mine (default: %u)"), EDC_DEFAULT_BYTES_PER_SIGOP));
    strUsage += HelpMessageOpt("-ebdatacarrier", 
		strprintf(_("Relay and mine data carrier transactions (default: %u)"), EDC_DEFAULT_ACCEPT_DATACARRIER));
    strUsage += HelpMessageOpt("-ebdatacarriersize", 
		strprintf(_("Maximum size of data in data carrier transactions we relay and mine (default: %u)"), EDC_MAX_OP_RETURN_RELAY));
    strUsage += HelpMessageOpt("-ebmempoolreplacement", 
		strprintf(_("Enable transaction replacement in the memory pool (default: %u)"), EDC_DEFAULT_ENABLE_REPLACEMENT));

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit Block creation options:"));
    strUsage += HelpMessageOpt("-ebblockminsize=<n>", 
		strprintf(_("Set minimum block size in bytes (default: %u)"), EDC_DEFAULT_BLOCK_MIN_SIZE));
    strUsage += HelpMessageOpt("-ebblockmaxsize=<n>", 
		strprintf(_("Set maximum block size in bytes (default: %d)"), EDC_DEFAULT_BLOCK_MAX_SIZE));
    strUsage += HelpMessageOpt("-ebblockprioritysize=<n>", 
		strprintf(_("Set maximum size of high-priority/low-fee transactions in bytes (default: %d)"), EDC_DEFAULT_BLOCK_PRIORITY_SIZE));
    if (showDebug)
        strUsage += HelpMessageOpt("-ebblockversion=<n>", "Override block version to test forking scenarios");

	////////////////////////////////////////////////////////////////////////
    strUsage += HelpMessageGroup(_("Equibit RPC server options:"));

    strUsage += HelpMessageOpt("-ebserver", 
		_("Accept command line and JSON-RPC commands"));
    strUsage += HelpMessageOpt("-ebrest", 
		strprintf(_("Accept public REST requests (default: %u)"), EDC_DEFAULT_REST_ENABLE));
    strUsage += HelpMessageOpt("-ebrpcbind=<addr>", 
		_("Bind to given address to listen for JSON-RPC connections. Use [host]:port notation for IPv6. This option can be specified multiple times (default: bind to all interfaces)"));
    strUsage += HelpMessageOpt("-ebrpccookiefile=<loc>", 
		_("Location of the auth cookie (default: data dir)"));
    strUsage += HelpMessageOpt("-ebrpcuser=<user>", 
		_("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-ebrpcpassword=<pw>", 
		_("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-ebrpcauth=<userpw>", 
		_("Username and hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcuser. This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-ebrpcport=<port>", 
		strprintf(_("Listen for JSON-RPC connections on <port> (default: %u or testnet: %u)"), BaseParams(CBaseChainParams::MAIN).RPCPort(), BaseParams(CBaseChainParams::TESTNET).RPCPort()));
    strUsage += HelpMessageOpt("-ebrpcallowip=<ip>", 
		_("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-ebrpcthreads=<n>", 
		strprintf(_("Set the number of threads to service RPC calls (default: %d)"), EDC_DEFAULT_HTTP_THREADS));
    if (showDebug) 
	{
        strUsage += HelpMessageOpt("-ebrpcworkqueue=<n>", 
			strprintf("Set the depth of the work queue to service RPC calls (default: %d)", EDC_DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-ebrpcservertimeout=<n>", 
			strprintf("Timeout during HTTP requests (default: %d)", EDC_DEFAULT_HTTP_SERVER_TIMEOUT));
    }

    return strUsage;
}
