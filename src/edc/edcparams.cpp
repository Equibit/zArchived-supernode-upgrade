// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcparams.h"
#include "edcutil.h"
#include "edcchainparams.h"
#include "edc/wallet/edcwallet.h"
#include "edcapp.h"
#include "utilmoneystr.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/foreach.hpp>
#include <sys/types.h>
#include <sys/stat.h>


namespace
{

const int64_t      EDC_DEFAULT_DB_CACHE               = 100;
const int64_t      EDC_MAX_DB_CACHE                   = sizeof(void*)>4?16384:1024;
const unsigned int EDC_MAX_OP_RETURN_RELAY            = 83;
const unsigned int EDC_MIN_BLOCKS_TO_KEEP             = 288;
const int64_t      EDC_MIN_DB_CACHE                   = 4;
const uint64_t     EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024;


const bool         EDC_DEFAULT_ACCEPT_DATACARRIER      = true;
const unsigned int EDC_DEFAULT_ANCESTOR_LIMIT          = 25;
const unsigned int EDC_DEFAULT_ANCESTOR_SIZE_LIMIT     = 101;

const unsigned int EDC_DEFAULT_BANSCORE_THRESHOLD      = 100;
const unsigned int EDC_DEFAULT_BLOCK_MAX_SIZE          = 750000;
const unsigned int EDC_DEFAULT_BLOCK_MIN_SIZE          = 0;
const unsigned int EDC_DEFAULT_BLOCK_PRIORITY_SIZE     = 0;
const bool         EDC_DEFAULT_BLOCKSONLY              = false;
const unsigned int EDC_DEFAULT_BYTES_PER_SIGOP         = 20;

const signed int   EDC_DEFAULT_CHECKBLOCKS             = EDC_MIN_BLOCKS_TO_KEEP;
const unsigned int EDC_DEFAULT_CHECKLEVEL              = 3;
const bool         EDC_DEFAULT_CHECKPOINTS_ENABLED     = true;
const char * const EDC_DEFAULT_CONF_FILENAME           = "equibit.conf";

const unsigned int EDC_DEFAULT_DESCENDANT_LIMIT        = 25;
const unsigned int EDC_DEFAULT_DESCENDANT_SIZE_LIMIT   = 101;
const bool         EDC_DEFAULT_DISABLE_SAFEMODE        = false;

const bool         EDC_DEFAULT_ENABLE_REPLACEMENT      = true;

const bool         EDC_DEFAULT_FEEFILTER               = true;
const bool         EDC_DEFAULT_FLUSHWALLET             = true;
const bool         EDC_DEFAULT_FORCEDNSSEED            = false;

const int          EDC_DEFAULT_HTTP_SERVER_TIMEOUT     = 30;
const int          EDC_DEFAULT_HTTP_THREADS            = 4;
const int          EDC_DEFAULT_HTTP_WORKQUEUE          = 16;

const unsigned int EDC_DEFAULT_KEYPOOL_SIZE            = 100;

const unsigned int EDC_DEFAULT_LIMITFREERELAY          = 15;
const bool         EDC_DEFAULT_LISTEN                  = true;
const bool         EDC_DEFAULT_LISTEN_ONION            = true;
const bool         EDC_DEFAULT_LOGIPS                  = false;
const bool         EDC_DEFAULT_LOGTIMESTAMPS           = true;
const bool         EDC_DEFAULT_LOGTIMEMICROS           = false;

const unsigned int EDC_DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
const unsigned int EDC_DEFAULT_MAX_MEMPOOL_SIZE        = 300;
const unsigned int EDC_DEFAULT_MAX_PEER_CONNECTIONS    = 125;
const unsigned int EDC_DEFAULT_MAX_SIG_CACHE_SIZE      = 40;
const int64_t      EDC_DEFAULT_MAX_TIME_ADJUSTMENT     = 70 * 60;
const int64_t      EDC_DEFAULT_MAX_TIP_AGE             = 24 * 60 * 60;
const uint64_t     EDC_DEFAULT_MAX_UPLOAD_TARGET       = 0;
const size_t       EDC_DEFAULT_MAXRECEIVEBUFFER        = 5 * 1000;
const size_t       EDC_DEFAULT_MAXSENDBUFFER           = 1 * 1000;
const unsigned int EDC_DEFAULT_MEMPOOL_EXPIRY          = 72;
const unsigned int EDC_DEFAULT_MISBEHAVING_BANTIME     = 60 * 60 * 24;  // Default 24-hour ban

const int          EDC_DEFAULT_NAME_LOOKUP             = true;

const bool         EDC_DEFAULT_PEERBLOOMFILTERS        = true;
const bool         EDC_DEFAULT_PERMIT_BAREMULTISIG     = true;
const bool         EDC_DEFAULT_PRINTPRIORITY           = false;
const bool         EDC_DEFAULT_PROXYRANDOMIZE          = true;

const bool         EDC_DEFAULT_RELAYPRIORITY           = true;
const bool         EDC_DEFAULT_REST_ENABLE             = false;

const int          EDC_DEFAULT_SCRIPTCHECK_THREADS     = 0;
const bool         EDC_DEFAULT_SEND_FREE_TRANSACTIONS  = false;
const bool         EDC_DEFAULT_SPEND_ZEROCONF_CHANGE   = true;
const bool         EDC_DEFAULT_STOPAFTERBLOCKIMPORT    = false;

const bool         EDC_DEFAULT_TESTSAFEMODE            = false;
const char * const EDC_DEFAULT_TOR_CONTROL             = "127.0.0.1:9051";
const CAmount      EDC_DEFAULT_TRANSACTION_MAXFEE      = 0.1 * COIN;
const unsigned int EDC_DEFAULT_TX_CONFIRM_TARGET       = 2;
const bool         EDC_DEFAULT_TXINDEX                 = false;

const bool         EDC_DEFAULT_UPNP                    = false;

const char *       EDC_DEFAULT_WALLET_DAT              = "wallet.dat";
const unsigned int EDC_DEFAULT_WALLET_DBLOGSIZE        = 100;
const bool         EDC_DEFAULT_WALLET_PRIVDB           = true;
const bool         EDC_DEFAULT_WHITELISTFORCERELAY     = true;
const bool         EDC_DEFAULT_WHITELISTRELAY          = true;

const std::string  COOKIEAUTH_FILE                     = ".cookie";
const char * const EQUIBIT_PID_FILENAME                = "equibit.pid";


boost::filesystem::path GetEquibitConfigFile()
{
	EDCparams & params = EDCparams::singleton();

    boost::filesystem::path pathConfigFile( params.conf );

    if (!pathConfigFile.is_complete())
        pathConfigFile = edcGetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

void InterpretNegativeSetting(
	std::string& strKey, 
	std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o')
    {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

void ReadEquibitConfigFile(
	              std::map<std::string, std::string> & mapSettingsRet,
    std::map<std::string, std::vector<std::string> > & mapMultiSettingsRet )
{
    boost::filesystem::ifstream streamConfig(GetEquibitConfigFile());
    if (!streamConfig.good())
        return; // No bitcoin.conf file is OK

    std::set<std::string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, 
	setOptions), end; it != end; ++it)
    {
        // Don't overwrite existing settings so command line settings override 
		// equibit.conf
		//
        std::string strKey = std::string("-") + it->string_key;
        std::string strValue = it->value[0];
        InterpretNegativeSetting(strKey, strValue);

        if (mapSettingsRet.count(strKey) == 0)
            mapSettingsRet[strKey] = strValue;

        mapMultiSettingsRet[strKey].push_back(strValue);
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
}

}

EDCparams::EDCparams()
{
	datadir = GetArg( "-ebdatadir", edcGetDataDir(true).string() );

	// First load the config file, which may contain more settings
	//
	conf = GetArg( "-ebconf", EDC_DEFAULT_CONF_FILENAME );

	try
	{
		ReadEquibitConfigFile( mapArgs, mapMultiArgs );
	}
	catch(const std::exception& e) 
	{
        fprintf(stderr,"Error reading configuration file: %s\n", e.what());
        configFileReadFailed = true;
    }
    configFileReadFailed = true;

	// Bool parameters
	acceptnonstdtxn     = GetBoolArg( "-ebacceptnonstdtxn", false );
	blocksonly          = GetBoolArg( "-ebblocksonly", EDC_DEFAULT_BLOCKSONLY );
	checkpoints         = GetBoolArg( "-ebcheckpoints", EDC_DEFAULT_CHECKPOINTS_ENABLED );
	datacarrier         = GetBoolArg( "-ebdatacarrier", EDC_DEFAULT_ACCEPT_DATACARRIER );
	disablesafemode     = GetBoolArg( "-ebdisablesafemode", EDC_DEFAULT_DISABLE_SAFEMODE );
	discover            = GetBoolArg( "-ebdiscover", true );
	dns                 = GetBoolArg( "-ebdns", EDC_DEFAULT_NAME_LOOKUP );
	dnsseed             = GetBoolArg( "-ebdnsseed", true );
	feefilter           = GetBoolArg( "-ebfeefilter", EDC_DEFAULT_FEEFILTER );
	flushwallet         = GetBoolArg( "-ebflushwallet",EDC_DEFAULT_FLUSHWALLET);
	forcednsseed        = GetBoolArg( "-ebforcednsseed", EDC_DEFAULT_FORCEDNSSEED );
	listen              = GetBoolArg( "-eblisten", EDC_DEFAULT_LISTEN );
	listenonion         = GetBoolArg( "-eblistenonion",EDC_DEFAULT_LISTEN_ONION);
	logips              = GetBoolArg( "-eblogips", EDC_DEFAULT_LOGIPS );
	logtimemicros       = GetBoolArg( "-eblogtimemicros", EDC_DEFAULT_LOGTIMEMICROS );
	logtimestamps       = GetBoolArg( "-eblogtimestamps", EDC_DEFAULT_LOGTIMESTAMPS );
	nodebug             = GetBoolArg( "-ebnodebug", false );
	regtest             = GetBoolArg( "-ebregtest", false );
	checkblockindex     = GetBoolArg( "-ebcheckblockindex", regtest );
	checkmempool        = GetBoolArg( "-ebcheckmempool", regtest );
	testnet             = GetBoolArg( "-ebtestnet", false );
	reindex             = GetBoolArg( "-ebreindex", false );
	printpriority       = GetBoolArg( "-ebprintpriority", EDC_DEFAULT_PRINTPRIORITY );
	printtoconsole      = GetBoolArg( "-ebprinttoconsole", false );
	privdb              = GetBoolArg( "-ebprivdb", EDC_DEFAULT_WALLET_PRIVDB );
	proxyrandomize      = GetBoolArg( "-ebproxyrandomize", EDC_DEFAULT_PROXYRANDOMIZE );
	relaypriority       = GetBoolArg( "-ebrelaypriority", EDC_DEFAULT_RELAYPRIORITY );
	rescan              = GetBoolArg( "-ebrescan", false );
	rest                = GetBoolArg( "-ebrest", EDC_DEFAULT_REST_ENABLE );
	salvagewallet       = GetBoolArg( "-ebsalvagewallet", false );
	sendfreetransactions= GetBoolArg( "-ebsendfreetransactions", EDC_DEFAULT_SEND_FREE_TRANSACTIONS );
	server              = GetBoolArg( "-ebserver", true );
	shrinkdebugfile     = GetBoolArg( "-ebshrinkdebugfile", !fDebug );
	spendzeroconfchange = GetBoolArg( "-ebspendzeroconfchange", EDC_DEFAULT_SPEND_ZEROCONF_CHANGE );
	stopafterblockimport= GetBoolArg( "-ebstopafterblockimport", EDC_DEFAULT_STOPAFTERBLOCKIMPORT );
	testsafemode        = GetBoolArg( "-ebtestsafemode", EDC_DEFAULT_TESTSAFEMODE );
	txindex             = GetBoolArg( "-ebtxindex", EDC_DEFAULT_TXINDEX );
	upgradewallet       = GetBoolArg( "-ebupgradewallet", false );
	upnp                = GetBoolArg( "-ebupnp", EDC_DEFAULT_UPNP );
	walletbroadcast     = GetBoolArg( "-ebwalletbroadcast", false );
	whitelistrelay      = GetBoolArg( "-ebwhitelistrelay", EDC_DEFAULT_WHITELISTRELAY );
	whitelistforcerelay = GetBoolArg( "-ebwhitelistforcerelay", EDC_DEFAULT_WHITELISTFORCERELAY );
	zapwallettxes       = GetBoolArg( "-ebzapwallettxes", false );

	// Int parameters
	banscore            = GetArg( "-ebbanscore", EDC_DEFAULT_BANSCORE_THRESHOLD );
	bantime             = GetArg( "-ebbantime", EDC_DEFAULT_MISBEHAVING_BANTIME );
	blockmaxsize        = GetArg( "-ebblockmaxsize", EDC_DEFAULT_BLOCK_MAX_SIZE );
	blockminsize        = GetArg( "-ebblockminsize", EDC_DEFAULT_BLOCK_MIN_SIZE );
	blockprioritysize   = GetArg( "-ebblockprioritysize", EDC_DEFAULT_BLOCK_PRIORITY_SIZE );
	blockversion        = GetArg( "-ebblockversion", 0 );
	bytespersigop       = GetArg( "-ebbytespersigop", EDC_DEFAULT_BYTES_PER_SIGOP );
	checkblocks         = GetArg( "-ebcheckblocks", EDC_DEFAULT_CHECKBLOCKS );
	checklevel          = GetArg( "-ebchecklevel", EDC_DEFAULT_CHECKLEVEL );
	datacarriersize     = GetArg( "-ebdatacarriersize", EDC_MAX_OP_RETURN_RELAY );
	dbcache             = GetArg( "-ebdbcache", EDC_DEFAULT_DB_CACHE );
	dblogsize           = GetArg( "-ebdblogsize", EDC_DEFAULT_WALLET_DBLOGSIZE );
	dropmessagestest    = GetArg( "-ebdropmessagestest", 0 );
	fuzzmessagetest     = GetArg( "-ebfuzzmessagetest", 10 );
	keypool             = GetArg( "-ebkeypool", EDC_DEFAULT_KEYPOOL_SIZE );
	limitancestorcount  = GetArg( "-eblimitancestorcount", EDC_DEFAULT_ANCESTOR_LIMIT );
	limitancestorsize   = GetArg( "-eblimitancestorsize", EDC_DEFAULT_ANCESTOR_SIZE_LIMIT );
	limitdescendantcount= GetArg( "-eblimitdescendantcount", EDC_DEFAULT_DESCENDANT_LIMIT );
	limitdescendantsize = GetArg( "-eblimitdescendantsize", EDC_DEFAULT_DESCENDANT_SIZE_LIMIT );
	limitfreerelay      = GetArg( "-eblimitfreerelay", EDC_DEFAULT_LIMITFREERELAY );
	maxconnections      = GetArg( "-ebmaxconnections", EDC_DEFAULT_MAX_PEER_CONNECTIONS );
	maxmempool          = GetArg( "-ebmaxmempool", EDC_DEFAULT_MAX_MEMPOOL_SIZE );
	maxorphantx         = GetArg( "-ebmaxorphantx", EDC_DEFAULT_MAX_ORPHAN_TRANSACTIONS );
	maxreceivebuffer    = GetArg( "-ebmaxreceivebuffer", EDC_DEFAULT_MAXRECEIVEBUFFER );
	maxsendbuffer       = GetArg( "-ebmaxsendbuffer", EDC_DEFAULT_MAXSENDBUFFER );
	maxsigcachesize     = GetArg( "-ebmaxsigcachesize", EDC_DEFAULT_MAX_SIG_CACHE_SIZE );
	maxtimeadjustment   = GetArg( "-ebmaxtimeadjustment", EDC_DEFAULT_MAX_TIME_ADJUSTMENT );
	maxtipage           = GetArg( "-ebmaxtipage", EDC_DEFAULT_MAX_TIP_AGE );
	maxtxfee            = GetArg( "-ebmaxtxfee", 0 );
	maxuploadtarget     = GetArg( "-ebmaxuploadtarget", EDC_DEFAULT_MAX_UPLOAD_TARGET );
	mempoolexpiry       = GetArg( "-ebmempoolexpiry", EDC_DEFAULT_MEMPOOL_EXPIRY );
	par                 = GetArg( "-ebpar", EDC_DEFAULT_SCRIPTCHECK_THREADS );
	peerbloomfilters    = GetArg( "-ebpeerbloomfilters", EDC_DEFAULT_PEERBLOOMFILTERS );
	permitbaremultisig  = GetArg( "-ebpermitbaremultisig", EDC_DEFAULT_PERMIT_BAREMULTISIG );
	port                = GetArg( "-ebport", regtest?18445:(testnet?18334:8334) );
	prune               = GetArg( "-ebprune", 0 );
	rpcport             = GetArg( "-ebrpcport", regtest?18331:(testnet?18331:8331) );
	rpcservertimeout    = GetArg( "-ebrpcservertimeout", EDC_DEFAULT_HTTP_SERVER_TIMEOUT );
	rpcthreads          = GetArg( "-ebrpcthreads", EDC_DEFAULT_HTTP_THREADS );
	rpcworkqueue        = GetArg( "-ebrpcworkqueue", EDC_DEFAULT_HTTP_WORKQUEUE );
	timeout             = GetArg( "-ebtimeout", EDC_DEFAULT_CONNECT_TIMEOUT );
	txconfirmtarget     = GetArg( "-ebtxconfirmtarget", EDC_DEFAULT_TX_CONFIRM_TARGET );


	// String parameters
	alertnotify         = GetArg( "-ebalertnotify", "" );
	blocknotify         = GetArg( "-ebblocknotify", "" );
	fallbackfee         = GetArg( "-ebfallbackfee", "" );
	mempoolreplacement  = GetArg( "-ebmempoolreplacement", EDC_DEFAULT_ENABLE_REPLACEMENT );
	minrelaytxfee       = GetArg( "-ebminrelaytxfee", "" );
	mintxfee            = GetArg( "-ebmintxfee", "" );
	onion               = GetArg( "-ebonion", "" );
	pid                 = GetArg( "-ebpid", EQUIBIT_PID_FILENAME );
	paytxfee            = GetArg( "-ebpaytxfee", "" );
	proxy               = GetArg( "-ebproxy", "" );
	rpccookiefile       = GetArg( "-ebrpccookiefile", COOKIEAUTH_FILE );
	rpcpassword         = GetArg( "-ebrpcpassword", "" );
	rpcuser             = GetArg( "-ebrpcuser", "" );
	torcontrol          = GetArg( "-ebtorcontrol", EDC_DEFAULT_TOR_CONTROL );
	torpassword         = GetArg( "-ebtorpassword", "" );
	wallet              = GetArg( "-ebwallet", EDC_DEFAULT_WALLET_DAT );
	walletnotify        = GetArg( "-ebwalletnotify", "" );

	// Vector of strings
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebaddnode"])
		addnode.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebbind"])
		bind.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebconnect"])
		connect.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebdebug"])
		debug.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebexternalip"])
		externalip.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebloadblock"])
		loadblock.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebonlynet"])
		onlynet.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebrpcallowip"])
		rpcallowip.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebrpcauth"])
		rpcauth.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebrpcbind"])
		rpcbind.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebseednode"])
		seednode.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebuacomment"])
		uacomment.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebwhitebind"])
		whitebind.push_back(e);
    BOOST_FOREACH(const std::string& e, mapMultiArgs["-ebwhitelist"])
		whitelist.push_back(e);
}

std::string EDCparams::helpMessage(HelpMessageMode mode)
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


EDCparams & EDCparams::singleton()
{
	static EDCparams theOneAndOnly;

	return theOneAndOnly;
}


bool EDCparams::validate() 
{
	if (!boost::filesystem::is_directory(edcGetDataDir(false)))
    {
		fprintf(stderr, "Error: Specified data directory \"%s\" does not "
			"exist.\n", datadir.c_str() );
        return false;
    }
	if( configFileReadFailed )
		return false;

    // Check for -ebtestnet or -ebregtest parameter (Params() calls are 
    // only valid after this clause)
    if (testnet && regtest)
	{
        fprintf( stderr, "Error: Invalid combination of -ebregtest and -ebtestnet.");
		return false;
	}

    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (bind.size() > 0) 
	{
        listen = true;
        edcLogPrintf("%s: parameter interaction: -ebbind set -> setting -eblisten=1\n", __func__);
    }
    if (whitebind.size() > 0) 
	{
        listen = true;
        edcLogPrintf("%s: parameter interaction: -ebwhitebind set -> setting -eblisten=1\n", __func__);
    }

    if ( connect.size() > 0 ) 
	{
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        dnsseed = false;
        edcLogPrintf("%s: parameter interaction: -dbconnect set -> setting -dbdnsseed=false\n", __func__);
        listen = false;
        edcLogPrintf("%s: parameter interaction: -dbconnect set -> setting -dblisten=0\n", __func__);
    }

    if (proxy.size() > 0 ) 
	{
        // to protect privacy, do not listen by default if a default proxy server is specified
        listen = false;
        edcLogPrintf("%s: parameter interaction: -ebproxy set -> setting -eblisten=0\n", __func__);

        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        upnp = false;
        edcLogPrintf("%s: parameter interaction: -ebproxy set -> setting -ebupnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        discover = false;
        edcLogPrintf("%s: parameter interaction: -ebproxy set -> setting -ebdiscover=0\n", __func__);
    }

    if (!listen) 
	{
        // do not map ports or try to retrieve public IP when not listening (pointless)
        upnp = false;
        edcLogPrintf("%s: parameter interaction: -eblisten=0 -> setting -ebupnp=0\n", __func__);
        discover = false;
        edcLogPrintf("%s: parameter interaction: -eblisten=0 -> setting -ebdiscover=0\n", __func__);
        listenonion = false;
        edcLogPrintf("%s: parameter interaction: -eblisten=0 -> setting -eblistenonion=0\n", __func__);
    }

    if (externalip.size() > 0 )
	{
        // if an explicit public IP is specified, do not try to find others
        discover = false;
        edcLogPrintf("%s: parameter interaction: -ebexternalip set -> setting -ebdiscover=0\n", __func__);
    }

    if (salvagewallet) 
	{
        // Rewrite just private keys: rescan to find transactions
        rescan = true;
        edcLogPrintf("%s: parameter interaction: -ebsalvagewallet=1 -> setting -ebrescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan
    if (zapwallettxes) 
	{
        rescan = true;
        edcLogPrintf("%s: parameter interaction: -ebzapwallettxes=<mode> -> setting -ebrescan=1\n", __func__);
    }

    // disable walletbroadcast and whitelistrelay in blocksonly mode
    if (blocksonly) 
	{
        whitelistrelay = false;
        edcLogPrintf("%s: parameter interaction: -ebblocksonly=1 -> setting -ebwhitelistrelay=0\n", __func__);
#ifdef ENABLE_WALLET
        walletbroadcast = false;
        edcLogPrintf("%s: parameter interaction: -ebblocksonly=1 -> setting -ebwalletbroadcast=0\n", __func__);
#endif
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (whitelistforcerelay) 
	{
        whitelistrelay = true;
        edcLogPrintf("%s: parameter interaction: -ebwhitelistforcerelay=1 -> setting -ebwhitelistrelay=1\n", __func__);
    }

	if (GetBoolArg( "-sysperms", false))
    {
#ifdef ENABLE_WALLET
        if (!disablewallet)
            return edcInitError("-sysperms is not allowed in combination "
                "with enabled wallet functionality");
#endif
    }
    else
    {
        umask(077);
    }

    // if using block pruning, then disable txindex
    if ( prune ) 
	{
        if (txindex)
            return edcInitError(_("Prune mode is incompatible with -txindex."));
#ifdef ENABLE_WALLET
        if (rescan) 
		{
            return edcInitError(_("Rescans are not possible in pruned mode. "
				"You will need to use -reindex which will download the whole "
				"blockchain again."));
        }
#endif
    }

    // mempool limits
    int64_t nMempoolSizeMax = maxmempool * 1000000;
    int64_t nMempoolSizeMin = limitdescendantsize * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return edcInitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    // block pruning; get the amount of disk space (in MiB) to allot for 
	// block & undo files
    int64_t nSignedPruneTarget = prune * 1024 * 1024;
    if (nSignedPruneTarget < 0) 
	{
        return edcInitError(_("Prune cannot be configured with a negative "
			"value."));
    }

	EDCapp & theApp = EDCapp::singleton();

    theApp.pruneTarget( (uint64_t) nSignedPruneTarget );
    if ( theApp.pruneTarget())
    {
        if ( theApp.pruneTarget() < EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES)
        {
            return edcInitError(strprintf(_("Prune configured below the "
				"minimum of %d MiB.  Please use a higher number."), 
				EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        edcLogPrintf("Prune configured to target %uMiB on disk for block and "
			"undo files.\n", theApp.pruneTarget() / 1024 / 1024);
        theApp.pruneMode( true );
    }

	return true;
}

