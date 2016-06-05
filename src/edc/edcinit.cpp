// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcinit.h"
#include "edcapp.h"
#include "edcparams.h"
#include "edcutil.h"
#include "edcmain.h"
#include "edcchainparams.h"
#include "clientversion.h"
#include "rpc/server.h"
#include "edcui_interface.h"
#include "utilmoneystr.h"
#include "edc/wallet/edcwallet.h"
#include <boost/interprocess/sync/file_lock.hpp>


extern void RegisterEquibitRPCCommands( CRPCTable & tableRPC );
extern void RegisterEquibitWalletRPCCommands(CRPCTable & tableRPC );

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE         = 0,
    BF_EXPLICIT     = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST    = (1U << 2),
};

#define MIN_CORE_FILEDESCRIPTORS 150


namespace
{

void edcInitLogging()
{
    edcLogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    edcLogPrintf("Equibit version %s (%s)\n", FormatFullVersion(), CLIENT_DATE);
}

std::string ResolveErrMsg(const char * const optname, const std::string& strBind)
{
    return strprintf(_("Cannot resolve -%s address: '%s'"), optname, strBind);
}

bool Bind(const CService &addr, unsigned int flags) 
{
    if (!(flags & BF_EXPLICIT) && IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0)) {
        if (flags & BF_REPORT_ERROR)
            return edcInitError(strError);
        return false;
    }
    return true;
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
    	if (params.minrelaytxfee.size() > 0 )
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

	    if ( params.peerbloomfilters )
   	    	theApp.localServices( theApp.localServices() | NODE_BLOOM );

    	// ** Step 4:app initialization: dir lock, daemonize, pidfile, debug log

    	std::string strDataDir = edcGetDataDir().string();

	    // Make sure only a single Equibit process is using the data directory.
   	 	boost::filesystem::path pathLockFile = edcGetDataDir() / ".lock";

		// empty lock file; created if it doesn't exist.
    	FILE * file = fopen(pathLockFile.string().c_str(), "a" ); 
	    if (file) 
			fclose(file);

   	 	try 
		{
        	static boost::interprocess::file_lock lock(
				pathLockFile.string().c_str());

        	if (!lock.try_lock())
            	return edcInitError(strprintf(_("Cannot obtain a lock on data "
					"directory %s. %s is probably already running."), 
					strDataDir, _(PACKAGE_NAME)));
    	} 
		catch( const boost::interprocess::interprocess_exception & e ) 
		{
        	return edcInitError(strprintf(_("Cannot obtain a lock on data "
				"directory %s. %s is probably already running.") + " %s.", 
				strDataDir, _(PACKAGE_NAME), e.what()));
    	}

    	CreatePidFile(edcGetPidFile(), getpid());

    	if (params.debug.size() > 0 )
        	edcShrinkDebugFile();

    	if (fPrintToDebugLog)
        	edcOpenDebugLog();

    	if (!params.logtimestamps)
        	edcLogPrintf("Startup time: %s\n", 
				DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));

    	edcLogPrintf("Default data directory %s\n", 
			edcGetDefaultDataDir().string());

    	edcLogPrintf("Using data directory %s\n", edcGetDataDir() );
    	edcLogPrintf("Using config file %s\n", edcGetConfigFile().string());
    	edcLogPrintf("Using at most %i connections (%i file descriptors "
			"available)\n", theApp.maxConnections(), nFD);

    	std::ostringstream strErrors;

    	edcLogPrintf("Using %u threads for script verification\n", params.par );
    	if ( params.par ) 
		{
        	for (int i=0; i < params.par; ++i )
            	threadGroup.create_thread( &edcThreadScriptCheck );
    	}

    	// Start the lightweight task scheduler thread
    	CScheduler::Function serviceLoop = 
			boost::bind(&CScheduler::serviceQueue, &scheduler);
	    threadGroup.create_thread(boost::bind(
			&edcTraceThread<CScheduler::Function>, "scheduler", serviceLoop));

    	// **************************** Step 5: verify wallet database integrity
#ifdef ENABLE_WALLET
    	if (!fDisableWallet) 
		{
        	if (!CEDCWallet::Verify())
            	return false;
    	}
#endif // ENABLE_WALLET

    	// ************************************* Step 6: network initialization

	    RegisterNodeSignals(GetEDCNodeSignals());

    	// sanitize comments per BIP-0014, format user agent and check total siz
    	std::vector<std::string> uacomments;
	    BOOST_FOREACH(std::string cmt, params.uacomment)
   	 	{
        	if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            	return edcInitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        	uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    	}
    	theApp.strSubVersion( FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments) );
    	if (theApp.strSubVersion().size() > MAX_SUBVERSION_LENGTH) 
		{
        	return edcInitError(strprintf(_("Total length of network version "
				"string (%i) exceeds maximum length (%i). Reduce the number or "
				"size of uacomments."),
            	theApp.strSubVersion().size(), MAX_SUBVERSION_LENGTH));
    	}

	    if ( params.onlynet.size() > 0 ) 
		{
	        std::set<enum Network> nets;
	        BOOST_FOREACH(const std::string& snet, params.onlynet ) 
			{
	            enum Network net = ParseNetwork(snet);
	            if (net == NET_UNROUTABLE)
	                return edcInitError(strprintf(_("Unknown network specified "
						"in -onlynet: '%s'"), snet));
	            nets.insert(net);
	        }
	        for (int n = 0; n < NET_MAX; n++) 
			{
	            enum Network net = (enum Network)n;
	            if (!nets.count(net))
	                SetLimited(net);
	        }
	    }
	
    	if (params.whitelist.size() > 0 ) 
		{
        	BOOST_FOREACH(const std::string& net, params.whitelist) 
			{
            	CSubNet subnet(net);
            	if (!subnet.IsValid())
                	return edcInitError(strprintf(_("Invalid netmask specified "
						"in -whitelist: '%s'"), net));
            	CNode::AddWhitelistedRange(subnet);
        	}
    	}

    	bool proxyRandomize = params.proxyrandomize;

    	// -ebproxy sets a proxy for all outgoing network traffic
    	// -ebnoproxy (or -proxy=0) as well as the empty string can be used to 
		// not set a proxy, this is the default
    	std::string proxyArg = params.proxy;
    	SetLimited(NET_TOR);

    	if (proxyArg != "" && proxyArg != "0") 
		{
        	proxyType addrProxy = proxyType(CService(proxyArg, 9050), 
				proxyRandomize);
        	if (!addrProxy.IsValid())
            	return edcInitError(strprintf(_("Invalid -proxy address: '%s'"),
					proxyArg));

        	SetProxy(NET_IPV4, addrProxy);
        	SetProxy(NET_IPV6, addrProxy);
        	SetProxy(NET_TOR, addrProxy);
        	SetNameProxy(addrProxy);
        	SetLimited(NET_TOR, false); // by default, -proxy sets onion as 
										// reachable, unless -noonion later
    	}

	    // -ebonion can be used to set only a proxy for .onion, or override 
		// normal proxy for .onion addresses
		// -ebnoonion (or -onion=0) disables connecting to .onion entirely
	    // An empty string is used to not override the onion proxy (in which 
		// case it defaults to -proxy set above, or none)
	    std::string onionArg = params.onion;
	    if (onionArg != "") 
		{
	        if (onionArg == "0") 
			{ 
				// Handle -noonion/-onion=0
	            SetLimited(NET_TOR); // set onions as unreachable
	        } 
			else 
			{
	            proxyType addrOnion = proxyType(CService(onionArg, 9050), 
					proxyRandomize);

	            if (!addrOnion.IsValid())
	                return edcInitError(strprintf(_("Invalid -onion address: "
						"'%s'"), onionArg));
	            SetProxy(NET_TOR, addrOnion);
	            SetLimited(NET_TOR, false);
	        }
	    }
	
    	// see Step 2: parameter interactions for more information about these
	    bool fBound = false;
	    if (params.listen) 
		{
	        if (params.bind.size() > 0 || params.whitebind.size() > 0 ) 
			{
	            BOOST_FOREACH(const std::string & strBind, params.bind) 
				{
	                CService addrBind;
	                if (!Lookup(strBind.c_str(), addrBind, edcGetListenPort(), false))
	                    return edcInitError(ResolveErrMsg("bind", strBind));
	                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
	            }
	            BOOST_FOREACH(const std::string& strBind, params.whitebind) 
				{
	                CService addrBind;
	                if (!Lookup(strBind.c_str(), addrBind, 0, false))
	                    return edcInitError(ResolveErrMsg("whitebind", strBind));
	                if (addrBind.GetPort() == 0)
	                    return edcInitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
	                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
	            }
	        }
	        else 
			{
	            struct in_addr inaddr_any;
	            inaddr_any.s_addr = INADDR_ANY;
	            fBound |= Bind(CService(in6addr_any, edcGetListenPort()), BF_NONE);
	            fBound |= Bind(CService(inaddr_any, edcGetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE);
	        }
	        if (!fBound)
	            return edcInitError(_("Failed to listen on any port. Use -eblisten=0 if you want this."));
	    }
	
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
    if (params.externalip.size() > 0 ) 
	{
        BOOST_FOREACH(const std::string& strAddr, params.externalip.size() > 0 )
		{
            CService addrLocal;
            if (Lookup(strAddr.c_str(), addrLocal, edcGetListenPort(), params.dns) && addrLocal.IsValid())
                edcAddLocal(addrLocal, LOCAL_MANUAL);
            else
                return edcInitError(ResolveErrMsg("externalip", strAddr));
        }
    }

    BOOST_FOREACH(const std::string& strDest, params.seednode)
        AddOneShot(strDest);

#if ENABLE_ZMQ
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs);

    if (pzmqNotificationInterface) 
	{
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif
    if (params.maxuploadtarget > 0 ) 
	{
        CNode::SetMaxOutboundTarget(params.maxuploadtarget, EDC_DEFAULT_MAX_UPLOAD_TARGET)*1024*1024);
    }

    // ********************************************************* Step 7: load block chain

    theApp.reindex( params.reindex );

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
    boost::filesystem::path blocksDir = edcGetDataDir() / "blocks";
    if (!boost::filesystem::exists(blocksDir))
    {
        boost::filesystem::create_directories(blocksDir);
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++) 
		{
            boost::filesystem::path source = edcGetDataDir() / strprintf("blk%04u.dat", i);
            if (!boost::filesystem::exists(source)) break;
            boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i-1);
            try 
			{
                boost::filesystem::create_hard_link(source, dest);
                edcLogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true;
            } 
			catch (const boost::filesystem::filesystem_error& e) 
			{
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                edcLogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                break;
            }
        }
        if (linked)
        {
            theApp.reindex( true );
        }
    }

    // cache size calculations
    int64_t nTotalCache = (params.dbcache << 20);
    nTotalCache = std::max(nTotalCache, EDC_MIN_DB_CACHE << 20); // total cache cannot be less than EDC_MIN_DB_CACHE
    nTotalCache = std::min(nTotalCache, EDC_MAX_DB_CACHE << 20); // total cache cannot be greated than EDC_MAX_DB_CACHE
    int64_t nBlockTreeDBCache = nTotalCache / 8;
    if (nBlockTreeDBCache > (1 << 21) && !params.txindex)
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache
    nTotalCache -= nCoinDBCache;
    theApp.coinCacheUsage( nTotalCache ); // the rest goes to in-memory cache
    edcLogPrintf("Cache configuration:\n");
    edcLogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    edcLogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    edcLogPrintf("* Using %.1fMiB for in-memory UTXO set\n", theApp.coinCacheUsage() * (1.0 / 1024 / 1024));

    bool fLoaded = false;
    int64_t nStart;

    while (!fLoaded) 
	{
        bool fReset = theApp.reindex();
        std::string strLoadError;

        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do 
		{
            try 
			{
                UnloadBlockIndex();
                delete theApp.coinsTip();
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete theApp.blocktree();

                theApp.blocktree( new CBlockTreeDB(nBlockTreeDBCache, false, theApp.reindex() ) );
                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, theApp.reindex() );
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                theApp.coinsTip( new CCoinsViewCache(pcoinscatcher) );

                if (theApp.reindex()) 
				{
                    theApp.blocktree()->WriteReindexing(true);
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (theApp.pruneMode())
                        CleanupBlockRevFiles();
                }

                if (!LoadBlockIndex()) 
				{
                    strLoadError = _("Error loading block database");
                    break;
                }

                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                if (!theApp.mapBlockIndex().empty() && edcMapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                    return edcInitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!InitBlockIndex(chainparams)) 
				{
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // Check for changed -txindex state
                if ( theApp.txIndex() != params.txindex) 
				{
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.
                if (theApp.havePruned() && !theApp.pruneMode()) 
				{
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                uiInterface.InitMessage(_("Verifying blocks..."));
                if (theApp.havePruned() && params.checkblocks > MIN_BLOCKS_TO_KEEP) 
				{
                    edcLogPrintf("Prune: pruned datadir may not have more than %d blocks; -checkblocks=%d may fail\n",
                        MIN_BLOCKS_TO_KEEP, params.checkblocks );
                }

                {
                    LOCK(cs_main);
                    CBlockIndex* tip = theApp.chainActive().Tip();
                    if (tip && tip->nTime > edcGetAdjustedTime() + 2 * 60 * 60) 
					{
                        strLoadError = _("The block database contains a block which appears to be from the future. "
                                "This may be due to your computer's date and time being set incorrectly. "
                                "Only rebuild the block database if you are sure that your computer's date and time are correct");
                        break;
                    }
                }

                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview, 
						params.checklevel,
                        params.checkblocks )) 
				{
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
            } 
			catch (const std::exception& e) 
			{
                if (params.debug.size() > 0 )
					edcLogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while(false);

        if (!fLoaded) 
		{
            // first suggest a reindex
            if (!fReset) 
			{
                bool fRet = uiInterface.ThreadSafeMessageBox(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"),
                    "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet) 
				{
                    theApp.reindex( true );
                    fRequestShutdown = false;
                } 
				else 
				{
                    edcLogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } 
			else 
			{
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
    if (fDisableWallet) 
	{
        theApp.walletMain( NULL );
        edcLogPrintf("Wallet disabled!\n");
    } 
	else 
	{
        CWallet::InitLoadWallet();
        if (!theApp.walletMain())
            return false;
    }
#else // ENABLE_WALLET
    edcLogPrintf("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

    // ********************************************************* Step 9: data directory maintenance

    // if pruning, unset the service bit and perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (theApp.pruneMode()) 
	{
        edcLogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        theApp.localServices( theApp.localServices()  & ~NODE_NETWORK );
        if (!theApp.reindex()) 
		{
            uiInterface.InitMessage(_("Pruning blockstore..."));
            PruneAndFlush();
        }
    }

    // ********************************************************* Step 10: import blocks

    if (params.blocknotify.size() > 0 )
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback);

    uiInterface.InitMessage(_("Activating best chain..."));
    // scan for better chains in the block chain database, that are not yet connected in the active best chain
    CValidationState state;
    if (!ActivateBestChain(state, chainparams))
        strErrors << "Failed to connect best block";

    std::vector<boost::filesystem::path> vImportFiles;
    if (params.loadblock.size() > 0 )
    {
        BOOST_FOREACH(const std::string& strFile, params.loadblock )
            vImportFiles.push_back(strFile);
    }
    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles));
    if (theApp.chainActive().Tip() == NULL) 
	{
        edcLogPrintf("Waiting for genesis block to be imported...\n");
        while (!fRequestShutdown && theApp.chainActive().Tip() == NULL)
            MilliSleep(10);
    }

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())
        return false;

    if (!strErrors.str().empty())
        return edcInitError(strErrors.str());

    RandAddSeedPerfmon();

    //// debug print
    edcLogPrintf("mapBlockIndex.size() = %u\n",  theApp.mapBlockIndex().size());
    edcLogPrintf("nBestHeight = %d\n",           theApp.chainActive().Height());
#ifdef ENABLE_WALLET
    edcLogPrintf("setKeyPool.size() = %u\n",     theApp.walletMain() ? theApp.walletMain()->setKeyPool.size() : 0);
    edcLogPrintf("mapWallet.size() = %u\n",      theApp.walletMain() ? theApp.walletMain()->mapWallet.size() : 0);
    edcLogPrintf("mapAddressBook.size() = %u\n", theApp.walletMain() ? theApp.walletMain()->mapAddressBook.size() : 0);
#endif

    if (params.listenonion )
        StartTorControl(threadGroup, scheduler);

    StartNode(threadGroup, scheduler);

    // Monitor the chain, and alert if we get blocks much quicker or slower than expected
    int64_t nPowTargetSpacing = Params().GetConsensus().nPowTargetSpacing;
    CScheduler::Function f = boost::bind(&PartitionCheck, &IsInitialBlockDownload,
                                         boost::ref(cs_main), boost::cref(theApp.indexBestHeader()), nPowTargetSpacing);
    scheduler.scheduleEvery(f, nPowTargetSpacing);

    // ********************************************************* Step 12: finished

    SetRPCWarmupFinished();
    uiInterface.InitMessage(_("Done loading"));

#ifdef ENABLE_WALLET
    if (theApp.walletMain()) 
	{
        // Add wallet transactions that aren't already in a block to mapTransactions
        theApp.walletMain()->ReacceptWalletTransactions();

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(theApp.walletMain()->strWalletFile)));
    }
#endif

    return !fRequestShutdown;
}


void edcShutdown()
{
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which AppInit2() failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("bitcoin-shutoff");
    mempool.AddTransactionsUpdated(1);

    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();
#ifdef ENABLE_WALLET
    if (theApp.walletMain())
        theApp.walletMain()->Flush(false);
#endif
    StopNode();
    StopTorControl();
    UnregisterNodeSignals(GetNodeSignals());

    if (fFeeEstimatesInitialized)
    {
        boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
        CAutoFile est_fileout(fopen(est_path.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION);
        if (!est_fileout.IsNull())
            mempool.WriteFeeEstimates(est_fileout);
        else
            LogPrintf("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    {
        LOCK(cs_main);
        if (theApp.coinsTip() != NULL) {
            FlushStateToDisk();
        }
        delete theApp.coinsTip();
        theApp.coinsTip( NULL );
        delete pcoinscatcher;
        pcoinscatcher = NULL;
        delete pcoinsdbview;
        pcoinsdbview = NULL;
        delete theApp.blocktree();
        theApp.blocktree( NULL );
    }
#ifdef ENABLE_WALLET
    if (theApp.walletMain())
        theApp.walletMain()->Flush(true);
#endif

#if ENABLE_ZMQ
    if (pzmqNotificationInterface) {
        UnregisterValidationInterface(pzmqNotificationInterface);
        delete pzmqNotificationInterface;
        pzmqNotificationInterface = NULL;
    }
#endif

#ifndef WIN32
    try {
        boost::filesystem::remove(GetPidFile());
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    UnregisterAllValidationInterfaces();
#ifdef ENABLE_WALLET
    delete theApp.walletMain();
    theApp.walletMain( NULL );
#endif
    globalVerifyHandle.reset();
    ECC_Stop();
    LogPrintf("%s: done\n", __func__);
}

struct CImportingNow
{
    CImportingNow() 
	{
		EDCapp & theApp = EDCapp::singleton();
        assert(theApp.importing() == false);
        theApp.importing( true );
    }

    ~CImportingNow() 
	{
		EDCapp & theApp = EDCapp::singleton();
        assert(theApp.importing() == true);
        theApp.importing( false );
    }
};

void edcThreadImport(std::vector<boost::filesystem::path> vImportFiles)
{
    const CChainParams& chainparams = Params();
    RenameThread("bitcoin-loadblk");
    // -reindex
    if (theApp.reindex()) {
        CImportingNow imp;
        int nFile = 0;
        while (true) {
            CDiskBlockPos pos(nFile, 0);
            if (!boost::filesystem::exists(GetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex
            FILE *file = OpenBlockFile(pos, true);
            if (!file)
                break; // This error is logged in OpenBlockFile
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(chainparams, file, &pos);
            nFile++;
        }
        theApp.blocktree()->WriteReindexing(false);
        theApp.reindex( false );
        LogPrintf("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        InitBlockIndex(chainparams);
    }

    // hardcoded $DATADIR/bootstrap.dat
    boost::filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (boost::filesystem::exists(pathBootstrap)) {
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            CImportingNow imp;
            boost::filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            LoadExternalBlockFile(chainparams, file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        } else {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock=
    BOOST_FOREACH(const boost::filesystem::path& path, vImportFiles) {
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file) {
            CImportingNow imp;
            LogPrintf("Importing blocks file %s...\n", path.string());
            LoadExternalBlockFile(chainparams, file);
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

    if (GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) {
        LogPrintf("Stopping after block import\n");
        StartShutdown();
    }
}

#endif
