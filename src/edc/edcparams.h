// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "amount.h"
#include "init.h"


const int          EDC_DEFAULT_CONNECT_TIMEOUT    = 5000;
const unsigned int EDC_DEFAULT_MIN_RELAY_TX_FEE   = 1000;
const CAmount      EDC_DEFAULT_TRANSACTION_MAXFEE = 0.1 * COIN;
const unsigned int EDC_DEFAULT_WALLET_DBLOGSIZE   = 100;
const bool         EDC_DEFAULT_WALLET_PRIVDB      = true;
const bool         EDC_DEFAULT_WALLETBROADCAST    = true;
const int          EDC_MAX_SCRIPTCHECK_THREADS    = 16;
const int64_t      EDC_MAX_DB_CACHE               = sizeof(void*)>4?16384:1024;
const int64_t      EDC_MIN_DB_CACHE               = 4;


// Equibit specific parameters
//
class EDCparams
{
public:

	std::string helpMessage( HelpMessageMode );
	bool validate();
	void dumpToLog() const;
	void checkParams() const;

	// Bool parameters
	bool acceptnonstdtxn;
	bool blocksonly;
	bool checkblockindex;
	bool checkmempool;
	bool checkparams;
	bool checkpoints;
	bool datacarrier;
	bool disablesafemode;
	bool disablewallet;
	bool discover;
	bool dns;
	bool dnsseed;
	bool feefilter;
	bool flushwallet;
	bool forcednsseed;
	bool listen;
	bool listenonion;
	bool logips;
	bool logtimemicros;
	bool logtimestamps;
	bool mempoolreplacement;
	bool nodebug;
	bool peerbloomfilters;
	bool permitbaremultisig;
	bool printpriority;
	bool regtest;
	bool testnet;
	bool printtoconsole;
	bool privdb;
	bool proxyrandomize;
	bool reindex;
	bool relaypriority;
	bool rescan;
	bool rest;
	bool salvagewallet;
	bool sendfreetransactions;
	bool server;
	bool shrinkdebugfile;
	bool spendzeroconfchange;
	bool stopafterblockimport;
	bool testsafemode;
	bool txindex;
	bool upgradewallet;
	bool upnp;
	bool walletbroadcast;
	bool whitelistforcerelay;
	bool whitelistrelay;

	// int parameters
	int64_t banscore;
	int64_t bantime;
	int64_t	blockmaxsize;
	int64_t blockminsize;
	int64_t blockprioritysize;
	int64_t blockversion;
	int64_t bytespersigop;
	int64_t checkblocks;
	int64_t checklevel;
	int64_t datacarriersize;
	int64_t dbcache;
	int64_t dblogsize;
	int64_t dropmessagestest;
	int64_t keypool;
	int64_t fuzzmessagetest;
	int64_t limitancestorcount;
	int64_t limitancestorsize;
	int64_t limitdescendantcount;
	int64_t limitdescendantsize;
	int64_t limitfreerelay;
	int64_t maxconnections;
	int64_t maxmempool;
	int64_t maxorphantx;
	int64_t maxreceivebuffer;
	int64_t maxsendbuffer;
	int64_t maxsigcachesize;
	int64_t maxtimeadjustment;

	/** If the tip is older than this (in seconds), the node is considered to be in initial block download. */
	int64_t maxtipage;

	int64_t maxtxfee;
	int64_t maxuploadtarget;
	int64_t mempoolexpiry;
	int64_t par;
	int64_t port;
	int64_t prune;
	int64_t rpcport;
	int64_t rpcservertimeout;
	int64_t rpcthreads;
	int64_t rpcworkqueue;
	int64_t sport;
	int64_t timeout;
	int64_t txconfirmtarget;
	int64_t zapwallettxes;

	// String parameters
	std::string alertnotify;
	std::string blocknotify;
	std::string conf;
	std::string datadir;
	std::string fallbackfee;
	std::string minrelaytxfee;
	std::string mintxfee;
	std::string onion;
	std::string paytxfee;
	std::string pid;
	std::string proxy;
	std::string rpccookiefile;
	std::string rpcpassword;
	std::string rpcuser;
	std::string torcontrol;
	std::string torpassword;
	std::string wallet;
	std::string walletnotify;

	// Vector of strings
	std::vector<std::string> addnode;
	std::vector<std::string> bind;
	std::vector<std::string> connect;
	std::vector<std::string> debug;
	std::vector<std::string> externalip;
	std::vector<std::string> loadblock;
	std::vector<std::string> onlynet;
	std::vector<std::string> rpcallowip;
	std::vector<std::string> rpcauth;
	std::vector<std::string> rpcbind;
	std::vector<std::string> seednode;
	std::vector<std::string> uacomment;
	std::vector<std::string> whitebind;
	std::vector<std::string> whitelist;

	static EDCparams & singleton();

	bool configFileReadFailed;  // Set to true if exception thrown during 
								// config file read

private:
	EDCparams();
};

