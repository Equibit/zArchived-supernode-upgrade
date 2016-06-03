#pragma once

#include "edctxmempool.h"

class CBlockTreeDB;


class EDCapp
{
public:
	int maxConnections() const		{ return maxConnections_; }
	void maxConnections( int mc )	{ maxConnections_ = mc; }

	int debug() const				{ return debug_; }
	void debug( int b )				{ debug_ = b; }

	CEDCTxMemPool & mempool() 		{ return mempool_; }

    CFeeRate & minRelayTxFee()		{ return minRelayTxFee_; }
    void minRelayTxFee( CFeeRate r ){ minRelayTxFee_ = r; }

	int scriptCheckThreads() const	{ return scriptCheckThreads_; }
	void scriptCheckThreads( int n ){ scriptCheckThreads_ = n; }

	uint64_t pruneTarget() const	{ return pruneTarget_; }
	void pruneTarget( uint64_t p )	{ pruneTarget_ = p; }

	bool pruneMode() const			{ return pruneMode_; }
	void pruneMode( bool p )		{ pruneMode_ = p; }

	int connectTimeout() const		{ return connectTimeout_; }
	void connectTimeout( int c )	{ connectTimeout_ = c; }

	CAmount maxTxFee() const		{ return maxTxFee_; }
	void maxTxFee( CAmount & m )	{ maxTxFee_ = m; }

	uint64_t localServices() const	{ return localServices_; }
	void localServices( uint64_t l ){ localServices_ = l; }

	bool enableReplacement() const	{ return enableReplacement_; }
	void enableReplacement( bool b) { enableReplacement_ = b; }

	uint64_t localHostNonce() const	{ return localHostNonce_; }
	void localHostNonce( uint64_t l){ localHostNonce_ = l; }

	CBlockTreeDB * blocktree() const	{ return blocktree_; }
	void blocktree( CBlockTreeDB * bt ) { blocktree_ = bt; }

	uint64_t lastBlockSize() const		{ return lastBlockSize_; }
	void lastBlockSize( uint64_t l )	{ lastBlockSize_ = l; }

	const CScript & coinbaseFlags() const	{ return COINBASE_FLAGS_; }
	CScript & coinbaseFlags()				{ return COINBASE_FLAGS_; }

	size_t coinCacheUsage() const	{ return coinCacheUsage_; }
	void coinCacheUsage( size_t c )	{ coinCacheUsage_ = c; }

	int64_t walletUnlockTime() const	{ return walletUnlockTime_; }
	void walletUnlockTime( int64_t w )  { walletUnlockTime_ = w; }

	uint64_t lastBlockTx() const		{ return lastBlockTx_; }
	void lastBlockTx( uint64_t ui )		{ lastBlockTx_ = ui; }


	static EDCapp & singleton();

private:
	EDCapp();

	EDCapp( const EDCapp & );
	EDCapp & operator = ( const EDCapp & );

	bool debug_;
	bool discover_;
	bool enableReplacement_;
	bool havePruned_;
	bool listen_;
	bool pruneMode_;
	bool sendFreeTransactions_;
	bool spendZeroConfChange_;
	bool txIndex_;
	bool isBareMultisigStd_;
	bool requireStandard_;

	int connectTimeout_;

	/** Maximum number of connections to simultaneously allow (aka connection 
	 *  slots) 
	 */
	int maxConnections_;
	int scriptCheckThreads_;

	int64_t walletUnlockTime_;

	unsigned int bytesPerSigOp_;
	unsigned int txConfirmTarget_;

	size_t coinCacheUsage_;

	/** Number of MiB of block files that we're trying to stay below. */
	uint64_t pruneTarget_;
	uint64_t localHostNonce_;
	uint64_t lastBlockSize_;
	
	uint64_t localServices_;
	uint64_t lastBlockTx_;

	/** Absolute maximum transaction fee (in satoshis) used by wallet
	 *  and mempool (rejects high fee in sendrawtransaction) 
	 */
	CAmount maxTxFee_;

	/* A fee rate smaller than this is considered zero fee (for relaying, 
     * mining and transaction creation) 
	 */
    CFeeRate minRelayTxFee_;

	CEDCTxMemPool mempool_;

	/* points to the active block tree (protected by EDC_cs_main) */
	CBlockTreeDB * blocktree_;

	/* Constant stuff for coinbase transactions we create: */
	CScript COINBASE_FLAGS_;
};

/*
	int64_t maxTipAge_;

	uint64_t lastBlockTx_;
	uint64_t lastBlockSize_;

	CAddrMan addrman_;
	std::vector<CEDCNode*> vNodes_;
	CCriticalSection cs_vNodes_;
	std::map<uint256, CEDCTransaction> mapRelay_;
	std::deque<std::pair<int64_t, uint256> > relayExpiration_;
	CCriticalSection cs_mapRelay_;
	limitedmap<uint256, int64_t> mapAlreadyAskedFor_;
	std::vector<std::string> addedNodes_;
	CCriticalSection cs_addedNodes_;
	NodeId lastNodeId_;
	CCriticalSection cs_lastNodeId_;
	std::string subVersion_;
	CCriticalSection cs_mapLocalHost_;
	std::map<CNetAddr, LocalServiceInfo> mapLocalHost_;
	CEDCWallet * walletMain_;
	CFeeRate payTxFee_;
	CEDCClientUIInterface uiInterface_;
	CCriticalSection cs_main_;
	BlockMap mapBlockIndex_;
	const std::string messageMagic_;
	CWaitableCriticalSection csBestBlock_;
	CConditionVariable cvBlockChange_;
	CBlockIndex * indexBestHeader_;
	CEDCCoinsViewCache * coinsTip_;
*/
