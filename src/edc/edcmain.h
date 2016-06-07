// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDCMAIN_H
#define EDC_EDCMAIN_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "main.h"
#include "amount.h"
#include "chain.h"
#include "edc/edccoins.h"
#include "edc/edcnet.h"
#include "script/script_error.h"
#include "sync.h"
#include "versionbits.h"

#include <algorithm>
#include <exception>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/unordered_map.hpp>

class CBlockIndex;
class CBlockTreeDB;
class CEDCBloomFilter;
class CEDCChainParams;
class CInv;
class CEDCScriptCheck;
class CEDCTxMemPool;
class CEDCValidationInterface;
class CValidationState;

struct CNodeStateStats;
struct LockPoints;

typedef boost::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;

extern CCriticalSection EDC_cs_main;
extern const std::string edcstrMessageMagic;
extern CWaitableCriticalSection edccsBestBlock;

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);

/** 
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 * 
 * @param[out]  state   This may be set to an Error state if any error occurred processing it, including during validation/connection/etc of otherwise unrelated blocks during reorganisation; or it may be set to an Invalid state if pblock is itself invalid (but this is not guaranteed even when the block is checked). If you want to *possibly* get feedback on whether pblock is valid, you must also install a CEDCValidationInterface (see validationinterface.h) - this will have its BlockChecked method called whenever *any* block completes validation.
 * @param[in]   pfrom   The node which we are receiving the block from; it is added to mapBlockSource and may be penalised if the block is invalid.
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and whitelisted peers.
 * @param[out]  dbp     If pblock is stored to disk (or already there), this will be set to its location.
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(CValidationState& state, const CEDCChainParams& chainparams, const CEDCNode* pfrom, const CEDCBlock* pblock, bool fForceProcessing, CDiskBlockPos* dbp);
/** Initialize a new block tree database + block data on disk */
bool edcInitBlockIndex(const CEDCChainParams& chainparams);
/** Load the block tree and coins database from disk */
bool edcLoadBlockIndex();
/** Unload database information */
void edcUnloadBlockIndex();

/** Process protocol messages received from a given node */
bool ProcessEDCMessages(CEDCNode* pfrom);

/**
 * Send queued protocol messages to be sent to a give node.
 *
 * @param[in]   pto             The node which we are sending messages to.
 */
bool SendEDCMessages(CEDCNode* pto);

/** Run an instance of the script checking thread */
void edcThreadScriptCheck();

/** Try to detect Partition (network isolation) attacks against us */
void edcPartitionCheck(bool (*initialDownloadCheck)(), CCriticalSection& cs, const CBlockIndex *const &bestHeader, int64_t nPowTargetSpacing);

/** Check whether we are doing an initial block download (synchronizing from disk or network) */
bool edcIsInitialBlockDownload();

/** Format a string that describes several potential problems detected by the core.
 * strFor can have three values:
 * - "rpc": get critical warnings, which should put the client in safe mode if non-empty
 * - "statusbar": get all warnings
 * - "gui": get all warnings, translated (where possible) for GUI
 * This function only returns the highest priority warning of the set selected by strFor.
 */
std::string edcGetWarnings(const std::string& strFor);

/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256 &hash, CEDCTransaction &tx, const Consensus::Params& params, uint256 &hashBlock, bool fAllowSlow = false);
/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(CValidationState& state, const CEDCChainParams& chainparams, const CEDCBlock* pblock = NULL);

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
void edcFindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);

/**
 *  Actually unlink the specified files
 */
void edcUnlinkPrunedFiles(std::set<int>& setFilesToPrune);

/** Create a new block index entry for a given block hash */
CBlockIndex * edcInsertBlockIndex(uint256 hash);
/** Get statistics from node state */
bool edcGetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);
/** Increase a node's misbehavior score. */
void edcMisbehaving(NodeId nodeid, int howmuch);
/** Flush all state, indexes and buffers to disk. */
void edcFlushStateToDisk();
/** Prune block files and flush state to disk. */
void edcPruneAndFlush();

/** (try to) add transaction to memory pool **/
bool AcceptToMemoryPool(CEDCTxMemPool& pool, CValidationState &state, const CEDCTransaction &tx, bool fLimitFree,
                        bool* pfMissingInputs, CFeeRate* txFeeRate, bool fOverrideMempoolLimit=false, const CAmount nAbsurdFee=0);

/** Get the BIP9 state for a given deployment at the current tip. */
ThresholdState EDCVersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** 
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way
 * @return number of sigops this transaction's outputs will produce when spent
 * @see CEDCTransaction::FetchInputs
 */
unsigned int GetLegacySigOpCount(const CEDCTransaction& tx);

/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 * 
 * @param[in] mapInputs Map of previous transactions that have outputs we're spending
 * @return maximum number of sigops required to validate this transaction's inputs
 * @see CEDCTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CEDCTransaction& tx, const CEDCCoinsViewCache& mapInputs);


/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set. If pvChecks is not NULL, script checks are pushed onto it
 * instead of being performed inline.
 */
bool CheckInputs(const CEDCTransaction& tx, CValidationState &state, const CEDCCoinsViewCache &view, bool fScriptChecks,
                 unsigned int flags, bool cacheStore, std::vector<CEDCScriptCheck> *pvChecks = NULL);

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CEDCTransaction& tx, CEDCCoinsViewCache &inputs, int nHeight);

/** Context-independent validity checks */
bool CheckTransaction(const CEDCTransaction& tx, CValidationState& state);

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CEDCNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CEDCNodeSignals& nodeSignals);

/**
 * Check if transaction is final and can be included in a block with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTx(const CEDCTransaction &tx, int nBlockHeight, int64_t nBlockTime);

/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CEDCTransaction &tx, int flags = -1);

/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical. Takes as input a list of heights at which tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CEDCTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current active chain.
 * Optionally stores in LockPoints the resulting height and time calculated and the hash
 * of the block needed for calculation or skips the calculation and uses the LockPoints
 * passed in for evaluation.
 * The LockPoints should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CEDCTransaction &tx, int flags, LockPoints* lp = NULL, bool useExistingLockPoints = false);

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction 
 */
class CEDCScriptCheck
{
private:
    CScript scriptPubKey;
    const CEDCTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    bool cacheStore;
    ScriptError error;

public:
    CEDCScriptCheck(): ptxTo(0), nIn(0), nFlags(0), cacheStore(false), error(SCRIPT_ERR_UNKNOWN_ERROR) {}
    CEDCScriptCheck(const CEDCCoins& txFromIn, const CEDCTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, bool cacheIn) :
        scriptPubKey(txFromIn.vout[txToIn.vin[nInIn].prevout.n].scriptPubKey),
        ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), cacheStore(cacheIn), error(SCRIPT_ERR_UNKNOWN_ERROR) { }

    bool operator()();

    void swap(CEDCScriptCheck &check) 
	{
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
    }

    ScriptError GetScriptError() const 
	{ 
		return error; 
	}
};


/** Functions for disk access for blocks */
bool WriteBlockToDisk(const CEDCBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart);
bool ReadBlockFromDisk(CEDCBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams);
bool ReadBlockFromDisk(CEDCBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams);

/** Functions for validating blocks and updating the block tree */

/** Context-independent validity checks */
bool CheckBlock(const CEDCBlock& block, CValidationState& state, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock(). */
bool ContextualCheckBlock(const CEDCBlock& block, CValidationState& state, CBlockIndex *pindexPrev);

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool ConnectBlock(const CEDCBlock& block, CValidationState& state, CBlockIndex* pindex, CEDCCoinsViewCache& coins,
                  const CEDCChainParams& chainparams, bool fJustCheck = false);

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified. */
bool DisconnectBlock(const CEDCBlock& block, CValidationState& state, const CBlockIndex* pindex, CEDCCoinsViewCache& coins, bool* pfClean = NULL);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with mainCS held) */
bool TestBlockValidity(CValidationState& state, const CEDCChainParams& chainparams, const CEDCBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CEDCVerifyDB {
public:
    CEDCVerifyDB();
    ~CEDCVerifyDB();
    bool VerifyDB(const CEDCChainParams& chainparams, CEDCCoinsView *coinsview, int nCheckLevel, int nCheckDepth);
};

/** Find the last common block between the parameter chain and a locator. */
extern CBlockIndex* edcFindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator);

/** Mark a block as invalid. */
extern bool edcInvalidateBlock(CValidationState& state, const CEDCChainParams& chainparams, CBlockIndex *pindex);

/** Remove invalidity status from a block and its descendants. */
extern bool edcResetBlockFailureFlags(CBlockIndex *pindex);

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by mainCS)
 * This is also true for mempool checks.
 */
extern int GetSpendHeight(const CEDCCoinsViewCache& inputs);

/**
 * Determine what nVersion a new block should use.
 */
extern int32_t edcComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

extern bool edcTestLockPointValidity(const LockPoints* lp);

extern boost::filesystem::path edcGetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);

extern bool edcLoadExternalBlockFile( const CEDCChainParams & chainparams, FILE * fileIn, CDiskBlockPos * dbp = NULL );

extern FILE* edcOpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false );

extern bool edcCheckDiskSpace(uint64_t nAdditionalBytes = 0);

#endif // EDC_EDCMAIN_H
