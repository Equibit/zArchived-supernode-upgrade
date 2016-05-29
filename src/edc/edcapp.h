#pragma once

#include "edctxmempool.h"


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

	unsigned int bytesPerSigOp_;
	unsigned int txConfirmTarget_;

	/** Number of MiB of block files that we're trying to stay below. */
	uint64_t pruneTarget_;
	
	/** Absolute maximum transaction fee (in satoshis) used by wallet
	 *  and mempool (rejects high fee in sendrawtransaction) 
	 */
	CAmount maxTxFee_;

	/* A fee rate smaller than this is considered zero fee (for relaying, 
     * mining and transaction creation) 
	 */
    CFeeRate minRelayTxFee_;

	CEDCTxMemPool mempool_;
};

/*
	int64_t maxTipAge_;

	uint64_t localServices_;
	uint64_t localHostNonce_;
	uint64_t edcnLastBlockTx_;
	uint64_t edcnLastBlockSize_;
	uint64_t lastBlockTx_;
	uint64_t lastBlockSize_;

	size_t coinCacheUsage_;

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
	CScript COINBASE_FLAGS_;
	CCriticalSection cs_main_;
	BlockMap mapBlockIndex_;
	const std::string messageMagic_;
	CWaitableCriticalSection csBestBlock_;
	CConditionVariable cvBlockChange_;
	CBlockIndex * indexBestHeader_;
	CEDCCoinsViewCache * coinsTip_;
	CBlockTreeDB * blocktree_;
*/
