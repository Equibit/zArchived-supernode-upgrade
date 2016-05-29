// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcinit.h"
#include "edcapp.h"
#include "edcparams.h"
#include "edcutil.h"
#include "edcchainparams.h"
#include "clientversion.h"
#include "rpc/server.h"
#include "edcui_interface.h"
#include "utilmoneystr.h"
#include "edc/wallet/edcwallet.h"


extern void RegisterEquibitRPCCommands( CRPCTable & tableRPC );
extern void RegisterEquibitWalletRPCCommands(CRPCTable & tableRPC );


#define MIN_CORE_FILEDESCRIPTORS 150


namespace
{

void edcInitLogging()
{
    edcLogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    edcLogPrintf("Equibit version %s (%s)\n", FormatFullVersion(), CLIENT_DATE);
}

}

bool EdcAppInit(
	boost::thread_group & threadGroup, 
		 	 CScheduler & scheduler)
{
	EDCparams & params = EDCparams::singleton();
	bool rc = params.validate();

	if( !rc )
		return rc;

	try
	{
        params.server = true;

    	// Set this early so that parameter interactions go to console
	    edcInitLogging();

        // ************************************* Step 1: setup
    	if (!SetupNetworking())
       	 	return edcInitError("Initializing networking failed");

    	// ************************************* Step 2: parameter interactions
    
		// Make sure enough file descriptors are available
    	int nBind = std::max((int)(params.bind.size() + params.whitebind.size()), 1);
	    int nUserMaxConnections = params.maxconnections;

		EDCapp & theApp = EDCapp::singleton();
    	theApp.maxConnections( std::max(nUserMaxConnections, 0) );

    	// Trim requested connection counts, to fit into system limitations
    	theApp.maxConnections( std::max(std::min( theApp.maxConnections(), 
			(int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0) );
    
		int nFD = RaiseFileDescriptorLimit( theApp.maxConnections() + 
			MIN_CORE_FILEDESCRIPTORS);
    	if (nFD < MIN_CORE_FILEDESCRIPTORS)
        	return edcInitError(_("Not enough file descriptors available."));
	    theApp.maxConnections( std::min(nFD - MIN_CORE_FILEDESCRIPTORS, theApp.maxConnections() ) );

    	if ( theApp.maxConnections() < nUserMaxConnections)
        	edcInitWarning(strprintf(_("Reducing -maxconnections from %d to %d,"
				" because of system limitations."), 
				nUserMaxConnections, theApp.maxConnections() ));

    	// ******************************** Step 3: parameter-to-internal-flags
    	theApp.debug( !params.debug.empty() );

    	// Special-case: if -ebdebug=0/-ebnodebug is set, turn off debugging 
		// messages
    	const std::vector<std::string>& categories = params.debug;

    	if ( params.nodebug || find( categories.begin(), categories.end(), 
		std::string("0")) != categories.end())
        	theApp.debug( false );

    	const CEDCChainParams & chainparams = edcParams();

    	// Checkmempool and checkblockindex default to true in regtest mode
		params.checkmempool = chainparams.DefaultConsistencyChecks() ? 1 : 0;

	    int ratio = std::min<int>(std::max<int>(params.checkmempool, 0), 
			1000000);

    	if (ratio != 0) 
		{
        	theApp.mempool().setSanityCheck(1.0 / ratio);
    	}
    	params.checkblockindex = chainparams.DefaultConsistencyChecks();

    	// -ebpar=0 means autodetect, but scriptCheckThreads==0 means no 
		// concurrency
    	theApp.scriptCheckThreads( params.par );
    	if ( theApp.scriptCheckThreads() <= 0)
        	theApp.scriptCheckThreads( theApp.scriptCheckThreads() + GetNumCores() );
    	if ( theApp.scriptCheckThreads() <= 1)
	        theApp.scriptCheckThreads( 0 );
    	else if ( theApp.scriptCheckThreads() > EDC_MAX_SCRIPTCHECK_THREADS)
        	theApp.scriptCheckThreads( EDC_MAX_SCRIPTCHECK_THREADS );

    	RegisterEquibitRPCCommands(tableRPC);

#ifdef ENABLE_WALLET
    	bool fDisableWallet = params.disablewallet;
    	if (!fDisableWallet)
        	RegisterEquibitWalletRPCCommands(tableRPC);
#endif
	    theApp.connectTimeout( params.timeout );
   	 	if ( theApp.connectTimeout() <= 0)
        	theApp.connectTimeout( EDC_DEFAULT_CONNECT_TIMEOUT );

    	// Fee-per-kilobyte amount considered the same as "free"
	    // If you are mining, be careful setting this:
   	 	// if you set it to zero then
    	// a transaction spammer can cheaply fill blocks using
    	// 1-satoshi-fee transactions. It should be set above the real
    	// cost to you of processing a transaction.
    	if (mapArgs.count("-minrelaytxfee"))
    	{
        	CAmount n = 0;
        	if (ParseMoney(params.minrelaytxfee, n) && n > 0)
            	theApp.minRelayTxFee( CFeeRate(n) );
        	else
            	return edcInitError(AmountErrMsg("ebminrelaytxfee", params.minrelaytxfee));
    	}
#ifdef ENABLE_WALLET
	    if (!CEDCWallet::ParameterInteraction())
   			return false;
#endif // ENABLE_WALLET


	}
	catch( const std::exception & e )
	{
        edcPrintExceptionContinue(&e, "EdcAppInit()");
		rc = false;
    } 
	catch (...) 
	{
        edcPrintExceptionContinue(NULL, "EdcAppInit()");
		rc = false;
    }

	return rc;
}

#if 0
    fAcceptDatacarrier = GetBoolArg("-datacarrier", EDC_DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);

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

    // ** Step 4:app initialization: dir lock, daemonize, pidfile, debug log

    // Initialize elliptic curve code
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
        return edcInitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), _(PACKAGE_NAME)));

    std::string strDataDir = edcGetDataDir().string();

    // Make sure only a single Bitcoin process is using the data directory.
    boost::filesystem::path pathLockFile = edcGetDataDir() / ".lock";
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);

    try {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
        if (!lock.try_lock())
            return edcInitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."), strDataDir, _(PACKAGE_NAME)));
    } catch(const boost::interprocess::interprocess_exception& e) {
        return edcInitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running.") + " %s.", strDataDir, _(PACKAGE_NAME), e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid());
#endif
    if (GetBoolArg("-shrinkdebugfile", !fDebug))
        edcShrinkDebugFile();

    if (fPrintToDebugLog)
        edcOpenDebugLog();

    if (!fLogTimestamps)
        edcLogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));
    edcLogPrintf("Default data directory %s\n", GetDefaultDataDir().string());
    edcLogPrintf("Using data directory %s\n", strDataDir);
    edcLogPrintf("Using config file %s\n", GetConfigFile().string());
    edcLogPrintf("Using at most %i connections (%i file descriptors available)\n", theApp.maxConnections(), nFD);
    std::ostringstream strErrors;

    edcLogPrintf("Using %u threads for script verification\n", nScriptCheckThreads);
    if (nScriptCheckThreads) {
        for (int i=0; i<nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
    }

    // Start the lightweight task scheduler thread
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler);
    threadGroup.create_thread(boost::bind(&edcTraceThread<CScheduler::Function>, "scheduler", serviceLoop));

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (params.server)
    {
        uiInterface.InitMessage.connect(SetRPCWarmupStatus);
        if (!AppInitServers(threadGroup))
            return edcInitError(_("Unable to start HTTP server. See debug log for details."));
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
            return edcInitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return edcInitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (mapArgs.count("-onlynet")) {
        std::set<enum Network> nets;
        BOOST_FOREACH(const std::string& snet, mapMultiArgs["-onlynet"]) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return edcInitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
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
                return edcInitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
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
            return edcInitError(strprintf(_("Invalid -proxy address: '%s'"), proxyArg));

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
                return edcInitError(strprintf(_("Invalid -onion address: '%s'"), onionArg));
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
                    return edcInitError(ResolveErrMsg("bind", strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
            }
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-whitebind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return edcInitError(ResolveErrMsg("whitebind", strBind));
                if (addrBind.GetPort() == 0)
                    return edcInitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
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
            return edcInitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (mapArgs.count("-externalip")) {
        BOOST_FOREACH(const std::string& strAddr, mapMultiArgs["-externalip"]) {
            CService addrLocal;
            if (Lookup(strAddr.c_str(), addrLocal, GetListenPort(), fNameLookup) && addrLocal.IsValid())
                AddLocal(addrLocal, LOCAL_MANUAL);
            else
                return edcInitError(ResolveErrMsg("externalip", strAddr));
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
    boost::filesystem::path blocksDir = edcGetDataDir() / "blocks";
    if (!boost::filesystem::exists(blocksDir))
    {
        boost::filesystem::create_directories(blocksDir);
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++) {
            boost::filesystem::path source = edcGetDataDir() / strprintf("blk%04u.dat", i);
            if (!boost::filesystem::exists(source)) break;
            boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i-1);
            try {
                boost::filesystem::create_hard_link(source, dest);
                edcLogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true;
            } catch (const boost::filesystem::filesystem_error& e) {
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                edcLogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
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
    edcLogPrintf("Cache configuration:\n");
    edcLogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    edcLogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    edcLogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

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
                    return edcInitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

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
                    edcLogPrintf("Prune: pruned datadir may not have more than %d blocks; -checkblocks=%d may fail\n",
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
                if (fDebug) edcLogPrintf("%s\n", e.what());
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
                    edcLogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return edcInitError(strLoadError);
            }
        }
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        edcLogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    edcLogPrintf(" block index %15dms\n", GetTimeMillis() - nStart);

    boost::filesystem::path est_path = edcGetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.
    if (!est_filein.IsNull())
        mempool.ReadFeeEstimates(est_filein);
    fFeeEstimatesInitialized = true;

    // ********************************************************* Step 8: load wallet
#ifdef ENABLE_WALLET
    if (fDisableWallet) {
        pwalletMain = NULL;
        edcLogPrintf("Wallet disabled!\n");
    } else {
        CWallet::InitLoadWallet();
        if (!pwalletMain)
            return false;
    }
#else // ENABLE_WALLET
    edcLogPrintf("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

    // ********************************************************* Step 9: data directory maintenance

    // if pruning, unset the service bit and perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (fPruneMode) {
        edcLogPrintf("Unsetting NODE_NETWORK on prune mode\n");
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
        edcLogPrintf("Waiting for genesis block to be imported...\n");
        while (!fRequestShutdown && chainActive.Tip() == NULL)
            MilliSleep(10);
    }

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())
        return false;

    if (!strErrors.str().empty())
        return edcInitError(strErrors.str());

    RandAddSeedPerfmon();

    //// debug print
    edcLogPrintf("mapBlockIndex.size() = %u\n",   mapBlockIndex.size());
    edcLogPrintf("nBestHeight = %d\n",                   chainActive.Height());
#ifdef ENABLE_WALLET
    edcLogPrintf("setKeyPool.size() = %u\n",      pwalletMain ? pwalletMain->setKeyPool.size() : 0);
    edcLogPrintf("mapWallet.size() = %u\n",       pwalletMain ? pwalletMain->mapWallet.size() : 0);
    edcLogPrintf("mapAddressBook.size() = %u\n",  pwalletMain ? pwalletMain->mapAddressBook.size() : 0);
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
#endif
