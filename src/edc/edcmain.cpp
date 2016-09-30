// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcmain.h"
#include "edcparams.h"
#include "addrman.h"
#include "arith_uint256.h"
#include "edcchainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "edc/consensus/edcconsensus.h"
#include "edc/consensus/edcmerkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "edcinit.h"
#include "edcmerkleblock.h"
#include "edc/edcnet.h"
#include "edc/policy/edcfees.h"
#include "edc/policy/edcpolicy.h"
#include "pow.h"
#include "edc/primitives/edcblock.h"
#include "edc/primitives/edctransaction.h"
#include "random.h"
#include "script/script.h"
#include "edc/script/edcsigcache.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "edctxdb.h"
#include "edctxmempool.h"
#include "edcui_interface.h"
#include "edcundo.h"
#include "edcutil.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "edcvalidationinterface.h"
#include "versionbits.h"
#include "edcapp.h"
#include "edc/message/edcmessage.h"
#include "edc/wallet/edcwallet.h"

#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/thread.hpp>

using namespace std;

#if defined(NDEBUG)
# error "Equibit cannot be compiled without assertions."
#endif

/**
 * Global state
 */
CCriticalSection EDC_cs_main;

const string edcstrMessageMagic = "Equibit Signed Message:\n";

CWaitableCriticalSection edccsBestBlock;

namespace
{
bool edcCheckBlock(const CEDCBlock& block, CValidationState& state, const Consensus::Params & consensusParams, int64_t nAdjustedTime, bool fCheckPOW = true, bool fCheckMerkleRoot = true);
bool edcContextualCheckBlock(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, CBlockIndex* pindexPrev);

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool edcConnectBlock(const CEDCBlock& block, CValidationState& state, CBlockIndex* pindex, CEDCCoinsViewCache& coins,
                  const CEDCChainParams& chainparams, bool fJustCheck = false);

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified. */
bool edcDisconnectBlock(const CEDCBlock& block, CValidationState& state, const CBlockIndex* pindex, CEDCCoinsViewCache& coins, bool* pfClean = NULL);


int64_t edcnTimeBestReceived = 0;

FeeFilterRounder edcfilterRounder(EDCapp::singleton().minRelayTxFee());

struct COrphanTx 
{
    CEDCTransaction tx;
    NodeId fromPeer;
};
map<uint256, COrphanTx> edcMapOrphanTransactions GUARDED_BY(EDC_cs_main);
map<uint256, set<uint256> > edcMapOrphanTransactionsByPrev GUARDED_BY(EDC_cs_main);
void edcEraseOrphansFor(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(EDC_cs_main);

/**
 * Returns true if there are nRequired or more blocks of minVersion or above
 * in the last Consensus::Params::nMajorityWindow blocks, starting at pstart and going backwards.
 */
bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams);
void edcCheckBlockIndex(const Consensus::Params& consensusParams);

bool edcFindBlockPos(CValidationState &state, CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false);

// Internal stuff
struct CBlockIndexWorkComparator
{
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) const 
	{
        // First sort by most total work, ...
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        // ... then by earliest time received, ...
        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

CBlockIndex *pindexBestInvalid;

/**
 * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
 * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
 * missing the data for the block.
 */
set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;
/** Number of nodes with fSyncStarted. */
int nSyncStarted = 0;
/** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
 * Pruned nodes may have entries where B is missing data.
 */
multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;

CCriticalSection cs_LastBlockFile;
std::vector<CBlockFileInfo> vinfoBlockFile;
int nLastBlockFile = 0;
/** Global flag to indicate we should check to see if there are
 *  block/undo files that should be deleted.  Set on startup
 *  or if we allocate more file space when we're in prune mode
 */
bool fCheckForPruning = false;

/**
 * Every received block is assigned a unique and increasing identifier, so we
 * know which one to give priority in case of a fork.
 */
CCriticalSection cs_nBlockSequenceId;

/** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
uint32_t nBlockSequenceId = 1;

/**
 * Sources of received blocks, saved to be able to send them reject
 * messages or ban them when processing happens afterwards. Protected by
 * EDC_cs_main.
 */
map<uint256, NodeId> mapBlockSource;

/**
 * Filter for transactions that were recently rejected by
 * AcceptToMemoryPool. These are not rerequested until the chain tip
 * changes, at which point the entire filter is reset. Protected by
 * EDC_cs_main.
 *
 * Without this filter we'd be re-requesting txs from each of our peers,
 * increasing bandwidth consumption considerably. For instance, with 100
 * peers, half of which relay a tx we don't accept, that might be a 50x
 * bandwidth increase. A flooding attacker attempting to roll-over the
 * filter using minimum-sized, 60byte, transactions might manage to send
 * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
 * two minute window to send invs to us.
 *
 * Decreasing the false positive rate is fairly cheap, so we pick one in a
 * million to make it highly unlikely for users to have issues with this
 * filter.
 *
 * Memory used: 1.3 MB
 */
boost::scoped_ptr<CRollingBloomFilter> recentRejects;
uint256 hashRecentRejectsChainTip;

/** Blocks that are in flight, and that are in the queue to be downloaded. Protected by EDC_cs_main. */
struct QueuedBlock 	
{
    uint256 hash;
    CBlockIndex* pindex;     //!< Optional.
    bool fValidatedHeaders;  //!< Whether this block has validated headers at the time of request.
};
map<uint256, pair<NodeId, list<QueuedBlock>::iterator> > mapBlocksInFlight;

/** Number of preferable block download peers. */
int nPreferredDownload = 0;

/** Dirty block index entries. */
set<CBlockIndex*> setDirtyBlockIndex;

/** Dirty block file entries. */
set<int> setDirtyFileInfo;

/** Number of peers from which we're downloading blocks. */
int nPeersWithValidatedDownloads = 0;

} // anon namespace

//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

int64_t edcGetAdjustedTime();

namespace 
{

struct CBlockReject 
{
    unsigned char chRejectCode;
    string strRejectReason;
    uint256 hashBlock;
};

/**
 * Maintain validation-specific state about nodes, protected by EDC_cs_main, instead
 * by CEDCNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState 
{
    //! The peer's address
    CService address;
    //! Whether we have a fully established connection.
    bool fCurrentlyConnected;
    //! Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    //! Whether this peer should be disconnected and banned (unless whitelisted).
    bool fShouldBan;
    //! String name of this peer (debugging/logging purposes).
    std::string name;
    //! List of asynchronously-determined block rejections to notify this peer about.
    std::vector<CBlockReject> rejects;
    //! The best known block we know this peer has announced.
    CBlockIndex *pindexBestKnownBlock;
    //! The hash of the last unknown block this peer has announced.
    uint256 hashLastUnknownBlock;
    //! The last full block we both have.
    CBlockIndex *pindexLastCommonBlock;
    //! The best header we have sent our peer.
    CBlockIndex *pindexBestHeaderSent;
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted;
    //! Since when we're stalling block download progress (in microseconds), or 0.
    int64_t nStallingSince;
    list<QueuedBlock> vBlocksInFlight;
    //! When the first entry in vBlocksInFlight started downloading. Don't care when vBlocksInFlight is empty.
    int64_t nDownloadingSince;
    int nBlocksInFlight;
    int nBlocksInFlightValidHeaders;
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload;
    //! Whether this peer wants invs or headers (when possible) for block announcements.
    bool fPreferHeaders;

    CNodeState() 
	{
        fCurrentlyConnected = false;
        nMisbehavior = 0;
        fShouldBan = false;
        pindexBestKnownBlock = NULL;
        hashLastUnknownBlock.SetNull();
        pindexLastCommonBlock = NULL;
        pindexBestHeaderSent = NULL;
        fSyncStarted = false;
        nStallingSince = 0;
        nDownloadingSince = 0;
        nBlocksInFlight = 0;
        nBlocksInFlightValidHeaders = 0;
        fPreferredDownload = false;
        fPreferHeaders = false;
    }
};

/** Map maintaining per-node state. Requires EDC_cs_main. */
map<NodeId, CNodeState> mapNodeState;

// Requires EDC_cs_main.
CNodeState *State(NodeId pnode) 
{
    map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
        return NULL;
    return &it->second;
}

int GetHeight()
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(EDC_cs_main);
    return theApp.chainActive().Height();
}

void UpdatePreferredDownload(CEDCNode* node, CNodeState* state)
{
    nPreferredDownload -= state->fPreferredDownload;

    // Whether this node should be marked as a preferred download node.
    state->fPreferredDownload = (!node->fInbound || node->fWhitelisted) && !node->fOneShot && !node->fClient;

    nPreferredDownload += state->fPreferredDownload;
}

void InitializeNode(NodeId nodeid, const CEDCNode *pnode) 
{
    LOCK(EDC_cs_main);
    CNodeState &state = mapNodeState.insert(std::make_pair(nodeid, CNodeState())).first->second;
    state.name = pnode->addrName;
    state.address = pnode->addr;
}

void FinalizeNode(NodeId nodeid) 
{
    LOCK(EDC_cs_main);
    CNodeState *state = State(nodeid);

    if (state->fSyncStarted)
        nSyncStarted--;

    if (state->nMisbehavior == 0 && state->fCurrentlyConnected) 
	{
        edcAddressCurrentlyConnected(state->address);
    }

    BOOST_FOREACH(const QueuedBlock& entry, state->vBlocksInFlight) 
	{
        mapBlocksInFlight.erase(entry.hash);
    }
    edcEraseOrphansFor(nodeid);
    nPreferredDownload -= state->fPreferredDownload;
    nPeersWithValidatedDownloads -= (state->nBlocksInFlightValidHeaders != 0);
    assert(nPeersWithValidatedDownloads >= 0);

    mapNodeState.erase(nodeid);

    if (mapNodeState.empty()) 
	{
        // Do a consistency check after the last peer is removed.
        assert(mapBlocksInFlight.empty());
        assert(nPreferredDownload == 0);
        assert(nPeersWithValidatedDownloads == 0);
    }
}

// Requires EDC_cs_main.
// Returns a bool indicating whether we requested this block.
bool MarkBlockAsReceived(const uint256& hash) 
{
    map<uint256, pair<NodeId, list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end()) 
	{
        CNodeState *state = State(itInFlight->second.first);
        state->nBlocksInFlightValidHeaders -= itInFlight->second.second->fValidatedHeaders;
        if (state->nBlocksInFlightValidHeaders == 0 && 
		    itInFlight->second.second->fValidatedHeaders) 
		{
            // Last validated block on the queue was received.
            nPeersWithValidatedDownloads--;
        }
        if (state->vBlocksInFlight.begin() == itInFlight->second.second) 
		{
            // First block on the queue was received, update the start download time for the next one
            state->nDownloadingSince = std::max(state->nDownloadingSince, GetTimeMicros());
        }
        state->vBlocksInFlight.erase(itInFlight->second.second);
        state->nBlocksInFlight--;
        state->nStallingSince = 0;
        mapBlocksInFlight.erase(itInFlight);
        return true;
    }
    return false;
}

// Requires EDC_cs_main.
void MarkBlockAsInFlight(
					   NodeId nodeid, 
			  const uint256 & hash, 
	const Consensus::Params & consensusParams, 
				CBlockIndex * pindex = NULL) 
{
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);

    QueuedBlock newentry = {hash, pindex, pindex != NULL};
    list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(), newentry);
    state->nBlocksInFlight++;
    state->nBlocksInFlightValidHeaders += newentry.fValidatedHeaders;

    if (state->nBlocksInFlight == 1) 
	{
        // We're starting a block download (batch) from this peer.
        state->nDownloadingSince = GetTimeMicros();
    }
    if (state->nBlocksInFlightValidHeaders == 1 && pindex != NULL) 
	{
        nPeersWithValidatedDownloads++;
    }
    mapBlocksInFlight[hash] = std::make_pair(nodeid, it);
}

/** Check whether the last unknown block a peer advertised is not yet known. */
void ProcessBlockAvailability(NodeId nodeid) 
{
	EDCapp & theApp = EDCapp::singleton();

    CNodeState *state = State(nodeid);
    assert(state != NULL);

    if (!state->hashLastUnknownBlock.IsNull()) 
	{
        BlockMap::iterator itOld = theApp.mapBlockIndex().find(state->hashLastUnknownBlock);
        if (itOld != theApp.mapBlockIndex().end() && itOld->second->nChainWork > 0) 
		{
            if (state->pindexBestKnownBlock == NULL || itOld->second->nChainWork >= state->pindexBestKnownBlock->nChainWork)
                state->pindexBestKnownBlock = itOld->second;
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

/** Update tracking information about which blocks a peer is assumed to have. */
void UpdateBlockAvailability(NodeId nodeid, const uint256 &hash) 
{
	EDCapp & theApp = EDCapp::singleton();

    CNodeState *state = State(nodeid);
    assert(state != NULL);

    ProcessBlockAvailability(nodeid);

    BlockMap::iterator it = theApp.mapBlockIndex().find(hash);
    if (it != theApp.mapBlockIndex().end() && it->second->nChainWork > 0) 
	{
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == NULL || 
            it->second->nChainWork >= state->pindexBestKnownBlock->nChainWork)
            state->pindexBestKnownBlock = it->second;
    } 
	else 
	{
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

// Requires EDC_cs_main
bool CanDirectFetch(const Consensus::Params &consensusParams)
{
	EDCapp & theApp = EDCapp::singleton();
    return theApp.chainActive().Tip()->GetBlockTime() > edcGetAdjustedTime() - consensusParams.nPowTargetSpacing * 20;
}

// Requires EDC_cs_main
bool PeerHasHeader(CNodeState *state, CBlockIndex *pindex)
{
    if (state->pindexBestKnownBlock && pindex == state->pindexBestKnownBlock->GetAncestor(pindex->nHeight))
        return true;
    if (state->pindexBestHeaderSent && pindex == state->pindexBestHeaderSent->GetAncestor(pindex->nHeight))
        return true;
    return false;
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-NULL. */
CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb) 
{
    if (pa->nHeight > pb->nHeight) 
	{
        pa = pa->GetAncestor(pb->nHeight);
    } 
	else if (pb->nHeight > pa->nHeight) 
	{
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) 
	{
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

/** Update pindexLastCommonBlock and add not-in-flight missing successors to 
 * vBlocks, until it has at most count entries. 
 */
void FindNextBlocksToDownload(
						 NodeId nodeid, 
				   unsigned int count, 
	std::vector<CBlockIndex*> & vBlocks, 
					   NodeId & nodeStaller) 
{
	EDCapp & theApp = EDCapp::singleton();
    if (count == 0)
        return;

    vBlocks.reserve(vBlocks.size() + count);
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Make sure pindexBestKnownBlock is up to date, we'll need it.
    ProcessBlockAvailability(nodeid);

    if (state->pindexBestKnownBlock == NULL || 
	    state->pindexBestKnownBlock->nChainWork < theApp.chainActive().Tip()->nChainWork)
	{
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBlock == NULL) 
	{
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBlock = theApp.chainActive()[std::min(state->pindexBestKnownBlock->nHeight, theApp.chainActive().Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
    // of its current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = LastCommonAncestor(state->pindexLastCommonBlock, state->pindexBestKnownBlock);
    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock)
        return;

    std::vector<CBlockIndex*> vToFetch;
    CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the best block we know the peer has, or more than BLOCK_DOWNLOAD_WINDOW + 1 beyond the last
    // linked block we have in common with this peer. The +1 is so we can detect stalling, namely if we would be able to
    // download that next block if the window were 1 larger.
    int nWindowEnd = state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
    int nMaxHeight = std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
    NodeId waitingfor = -1;
    while (pindexWalk->nHeight < nMaxHeight) 
	{
        // Read up to 128 (or more, if more blocks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownBlock) into vToFetch. We fetch 128, because CBlockIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBlocks.size(), 128));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBlock->GetAncestor(pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--) 
		{
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBlocks. In the mean time, update
        // pindexLastCommonBlock as long as all ancestors are already downloaded, or if it's
        // already part of our chain (and therefore don't need it even if pruned).
        BOOST_FOREACH(CBlockIndex* pindex, vToFetch) 
		{
            if (!pindex->IsValid(BLOCK_VALID_TREE)) 
			{
                // We consider the chain that this peer is on invalid.
                return;
            }
            if (pindex->nStatus & BLOCK_HAVE_DATA || theApp.chainActive().Contains(pindex)) 
			{
                if (pindex->nChainTx)
                    state->pindexLastCommonBlock = pindex;
            } 
			else if (mapBlocksInFlight.count(pindex->GetBlockHash()) == 0) 
			{
                // The block is not already downloaded, and not yet in flight.
                if (pindex->nHeight > nWindowEnd) 
				{
                    // We reached the end of the window.
                    if (vBlocks.size() == 0 && waitingfor != nodeid) 
					{
                        // We aren't able to fetch anything, but we would be if the download window was one larger.
                        nodeStaller = waitingfor;
                    }
                    return;
                }

                vBlocks.push_back(pindex);
                if (vBlocks.size() == count) 
				{
                    return;
                }
            } 
			else if (waitingfor == -1) 
			{
                // This is the first already-in-flight block.
                waitingfor = mapBlocksInFlight[pindex->GetBlockHash()].first;
            }
        }
    }
}

} // anon namespace

bool edcGetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) 
{
    LOCK(EDC_cs_main);
    CNodeState *state = State(nodeid);
    if (state == NULL)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight = state->pindexBestKnownBlock ? state->pindexBestKnownBlock->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock ? state->pindexLastCommonBlock->nHeight : -1;
    BOOST_FOREACH(const QueuedBlock& queue, state->vBlocksInFlight) 
	{
        if (queue.pindex)
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
    }
    return true;
}

void RegisterNodeSignals(CEDCNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.connect(&GetHeight);
    nodeSignals.ProcessMessages.connect(&edcProcessMessages);
    nodeSignals.SendMessages.connect(&edcSendMessages);
    nodeSignals.InitializeNode.connect(&InitializeNode);
    nodeSignals.FinalizeNode.connect(&FinalizeNode);
}

void UnregisterNodeSignals(CEDCNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.disconnect(&GetHeight);
    nodeSignals.ProcessMessages.disconnect(&edcProcessMessages);
    nodeSignals.SendMessages.disconnect(&edcSendMessages);
    nodeSignals.InitializeNode.disconnect(&InitializeNode);
    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
}

CBlockIndex* edcFindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
	EDCapp & theApp = EDCapp::singleton();
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, locator.vHave) 
	{
        BlockMap::iterator mi = theApp.mapBlockIndex().find(hash);
        if (mi != theApp.mapBlockIndex().end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (chain.Contains(pindex))
                return pindex;
        }
    }
    return chain.Genesis();
}

//////////////////////////////////////////////////////////////////////////////
//
// edcMapOrphanTransactions
//

bool AddOrphanTx(const CEDCTransaction& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(EDC_cs_main)
{
    uint256 hash = tx.GetHash();
    if (edcMapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CEDCTransaction::CURRENT_VERSION);
    if (sz > 5000)
    {
        edcLogPrint("mempool", "ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString());
        return false;
    }

    edcMapOrphanTransactions[hash].tx = tx;
    edcMapOrphanTransactions[hash].fromPeer = peer;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
        edcMapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    edcLogPrint("mempool", "stored orphan tx %s (mapsz %u prevsz %u)\n", hash.ToString(),
             edcMapOrphanTransactions.size(), edcMapOrphanTransactionsByPrev.size());
    return true;
}

namespace
{

void EraseOrphanTx(uint256 hash) EXCLUSIVE_LOCKS_REQUIRED(EDC_cs_main)
{
    map<uint256, COrphanTx>::iterator it = edcMapOrphanTransactions.find(hash);
    if (it == edcMapOrphanTransactions.end())
        return;
    BOOST_FOREACH(const CEDCTxIn& txin, it->second.tx.vin)
    {
        map<uint256, set<uint256> >::iterator itPrev = edcMapOrphanTransactionsByPrev.find(txin.prevout.hash);
        if (itPrev == edcMapOrphanTransactionsByPrev.end())
            continue;
        itPrev->second.erase(hash);
        if (itPrev->second.empty())
            edcMapOrphanTransactionsByPrev.erase(itPrev);
    }
    edcMapOrphanTransactions.erase(it);
}

void edcEraseOrphansFor(NodeId peer)
{
    int nErased = 0;
    map<uint256, COrphanTx>::iterator iter = edcMapOrphanTransactions.begin();
    while (iter != edcMapOrphanTransactions.end())
    {
        map<uint256, COrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer)
        {
            EraseOrphanTx(maybeErase->second.tx.GetHash());
            ++nErased;
        }
    }
    if (nErased > 0) edcLogPrint("mempool", "Erased %d orphan tx from peer %d\n", nErased, peer);
}

}

unsigned int edcLimitOrphanTxSize(unsigned int nMaxOrphans) EXCLUSIVE_LOCKS_REQUIRED(EDC_cs_main)
{
    unsigned int nEvicted = 0;
    while (edcMapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, COrphanTx>::iterator it = edcMapOrphanTransactions.lower_bound(randomhash);
        if (it == edcMapOrphanTransactions.end())
            it = edcMapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

bool IsFinalTx(
	const CEDCTransaction & tx, 
						int nBlockHeight, 
					int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin) 
	{
        if (!(txin.nSequence == CEDCTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

bool CheckFinalTx(const CEDCTransaction &tx, int flags)
{
	EDCapp & theApp = EDCapp::singleton();
    AssertLockHeld(EDC_cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses theApp.chainActive().Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CEDCBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than theApp.chainActive().Height().
    const int nBlockHeight = theApp.chainActive().Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if EDC_LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & EDC_LOCKTIME_MEDIAN_TIME_PAST)
                             ? theApp.chainActive().Tip()->GetMedianTimePast()
                             : edcGetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

namespace
{
/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
std::pair<int, int64_t> CalculateSequenceLocks(
	const CEDCTransaction & tx, 
						int flags, 
		 std::vector<int> * prevHeights, 
		const CBlockIndex & block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & EDC_LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) 
	{
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) 
	{
        const CEDCTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CEDCTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) 
		{
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CEDCTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) 
		{
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CEDCTxIn::SEQUENCE_LOCKTIME_MASK) << CEDCTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } 
		else 
		{
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CEDCTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}
}

bool SequenceLocks(
	const CEDCTransaction & tx, 
						int flags, 
		 std::vector<int> * prevHeights, 
		const CBlockIndex & block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool edcTestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(EDC_cs_main);
    assert(lp);

	EDCapp & theApp = EDCapp::singleton();

    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) 
	{
        // Check whether theApp.chainActive() is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!theApp.chainActive().Contains(lp->maxInputBlock)) 
		{
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(
    const CEDCTransaction & tx, 
					    int flags, 
               LockPoints * lp, 
			           bool useExistingLockPoints)
{
	EDCapp & theApp = EDCapp::singleton();

    AssertLockHeld(EDC_cs_main);
    AssertLockHeld(theApp.mempool().cs);

    CBlockIndex* tip = theApp.chainActive().Tip();
    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses theApp.chainActive().Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than theApp.chainActive().Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) 
	{
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else 
	{
        // coinsTip contains the UTXO set for theApp.chainActive().Tip()
        CEDCCoinsViewMemPool viewMemPool(theApp.coinsTip(), theApp.mempool());
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());

        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) 
		{
            const CEDCTxIn& txin = tx.vin[txinIndex];
            CEDCCoins coins;
            if (!viewMemPool.GetCoins(txin.prevout.hash, coins)) 
			{
                return edcError("%s: Missing input", __func__);
            }
            if (coins.nHeight == MEMPOOL_HEIGHT) 
			{
                // Assume all theApp.mempool() transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } 
			else 
			{
                prevheights[txinIndex] = coins.nHeight;
            }
        }

        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) 
		{
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for theApp.mempool() txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a theApp.mempool() input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            BOOST_FOREACH(int height, prevheights) 
			{
                // Can ignore theApp.mempool() inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) 
				{
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

unsigned int GetLegacySigOpCount(const CEDCTransaction & tx)
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CEDCTxOut& txout, tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(
	   const CEDCTransaction & tx, 
	const CEDCCoinsViewCache & inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CEDCTxOut &prevout = inputs.GetOutputFor(tx.vin[i]);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

bool CheckTransaction(const CEDCTransaction& tx, CValidationState &state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > EDC_MAX_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    BOOST_FOREACH(const CEDCTxOut& txout, tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

void LimitMempoolSize(CEDCTxMemPool& pool, size_t limit, unsigned long age) 
{
	EDCapp & theApp = EDCapp::singleton();

    int expired = pool.Expire(GetTime() - age);
    if (expired != 0)
        edcLogPrint("mempool", "Expired %i transactions from the memory pool\n", expired);

    std::vector<uint256> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    BOOST_FOREACH(const uint256& removed, vNoSpendsRemaining)
        theApp.coinsTip()->Uncache(removed);
}

bool AcceptToMemoryPoolWorker(
			CEDCTxMemPool & pool, 
		 CValidationState & state, 
	const CEDCTransaction & tx, 
					   bool fLimitFree,
					 bool * pfMissingInputs, 
					   bool fOverrideMempoolLimit, 
			const CAmount & nAbsurdFee,
     std::vector<uint256> & vHashTxnToUncache)
{
    const uint256 hash = tx.GetHash();
    AssertLockHeld(EDC_cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Rather not work on nonstandard transactions (unless -eb_testnet/-eb_regtest)
    string reason;
	EDCparams & params = EDCparams::singleton();
    if (!params.acceptnonstdtxn && !IsStandardTx(tx, reason))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);

    // Don't relay version 2 transactions until CSV is active, and we can be
    // sure that such transactions will be mined (unless we're on
    // -eb_testnet/-eb_regtest).
    const CEDCChainParams& chainparams = edcParams();
    if (!params.acceptnonstdtxn && 
		tx.nVersion >= 2 && 
		edcVersionBitsTipState(chainparams.GetConsensus(), 
			Consensus::DEPLOYMENT_CSV) != THRESHOLD_ACTIVE) 
	{
        return state.DoS(0, false, REJECT_NONSTANDARD, "premature-version2-tx");
    }

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our theApp.mempool() filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash))
        return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-in-mempool");

    // Check for conflicts with in-memory transactions
    set<uint256> setConflicts;
    {
    LOCK(pool.cs); // protect pool.mapNextTx
    BOOST_FOREACH(const CEDCTxIn &txin, tx.vin)
    {
        if (pool.mapNextTx.count(txin.prevout))
        {
            const CEDCTransaction *ptxConflicting = pool.mapNextTx[txin.prevout].ptx;
            if (!setConflicts.count(ptxConflicting->GetHash()))
            {
                // Allow opt-out of transaction replacement by setting
                // nSequence >= maxint-1 on all inputs.
                //
                // maxint-1 is picked to still allow use of nLockTime by
                // non-replacable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                if (params.mempoolreplacement)
                {
                    BOOST_FOREACH(const CEDCTxIn &txin, ptxConflicting->vin)
                    {
                        if (txin.nSequence < std::numeric_limits<unsigned int>::max()-1)
                        {
                            fReplacementOptOut = false;
                            break;
                        }
                    }
                }
                if (fReplacementOptOut)
                    return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");

                setConflicts.insert(ptxConflicting->GetHash());
            }
        }
    }
    }

    {
		EDCapp & theApp = EDCapp::singleton();
        CEDCCoinsView dummy;
        CEDCCoinsViewCache view(&dummy);

        CAmount nValueIn = 0;
        LockPoints lp;
        {
        LOCK(pool.cs);
        CEDCCoinsViewMemPool viewMemPool(theApp.coinsTip(), pool);
        view.SetBackend(viewMemPool);

        // do we already have it?
        bool fHadTxInCache = theApp.coinsTip()->HaveCoinsInCache(hash);
        if (view.HaveCoins(hash)) 
		{
            if (!fHadTxInCache)
                vHashTxnToUncache.push_back(hash);
            return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-known");
        }

        // do all inputs exist?
        // Note that this does not check for the presence of actual outputs (see the next check for that),
        // and only helps with filling in pfMissingInputs (to determine missing vs spent).
        BOOST_FOREACH(const CEDCTxIn txin, tx.vin) 
		{
            if (!theApp.coinsTip()->HaveCoinsInCache(txin.prevout.hash))
                vHashTxnToUncache.push_back(txin.prevout.hash);
            if (!view.HaveCoins(txin.prevout.hash)) 
			{
                if (pfMissingInputs)
                    *pfMissingInputs = true;
                return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
            }
        }

        // are the actual inputs available?
        if (!view.HaveInputs(tx))
            return state.Invalid(false, REJECT_DUPLICATE, "bad-txns-inputs-spent");

        // Bring the best block into scope
        view.GetBestBlock();

        nValueIn = view.GetValueIn(tx);

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // block; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
        // CoinsViewCache instead of create its own
        if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!params.acceptnonstdtxn && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        unsigned int nSigOps = GetLegacySigOpCount(tx);
        nSigOps += GetP2SHSigOpCount(tx, view);

        CAmount nValueOut = tx.GetValueOut();
        CAmount nFees = nValueIn-nValueOut;
        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        double nPriorityDummy = 0;
        pool.ApplyDeltas(hash, nPriorityDummy, nModifiedFees);

        CAmount inChainInputValue;
        double dPriority = view.GetPriority(tx, theApp.chainActive().Height(), inChainInputValue);

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure EDC_COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        BOOST_FOREACH(const CEDCTxIn &txin, tx.vin) 
		{
            const CEDCCoins *coins = view.AccessCoins(txin.prevout.hash);
            if (coins->IsCoinBase()) 
			{
                fSpendsCoinbase = true;
                break;
            }
        }

        CEDCTxMemPoolEntry entry(tx, nFees, GetTime(), dPriority, theApp.chainActive().Height(), pool.HasNoInputsOf(tx), inChainInputValue, fSpendsCoinbase, nSigOps, lp);
        unsigned int nSize = entry.GetTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // EDC_MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if ((nSigOps > MAX_STANDARD_TX_SIGOPS) || (params.bytespersigop && nSigOps > nSize / params.bytespersigop))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d", nSigOps));

        CAmount mempoolRejectFee = pool.GetMinFee( params.maxmempool * 1000000).GetFee(nSize);
        if (mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) 
		{
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, 
				"mempool min fee not met", false, 
				strprintf("%d < %d", nFees, mempoolRejectFee));
        } 
		else if (params.relaypriority && 
		nModifiedFees < theApp.minRelayTxFee().GetFee(nSize) && 
		!AllowFree(entry.GetPriority(theApp.chainActive().Height() + 1))) 
		{
            // Require that free transactions have sufficient priority to be mined in the next block.
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient priority");
        }

        // Continuously rate-limit free (really, very-low-fee) transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nModifiedFees < theApp.minRelayTxFee().GetFee(nSize))
        {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -eb_limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount + nSize >= params.limitfreerelay * 10 * 1000)
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "rate limited free transaction");
            edcLogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }

        if (nAbsurdFee && nFees > nAbsurdFee)
            return state.Invalid(false,
                REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));

        // Calculate in-mempool ancestors, up to a limit.
        CEDCTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = params.limitancestorcount;
        size_t nLimitAncestorSize = params.limitancestorsize * 1000;
        size_t nLimitDescendants = params.limitdescendantcount;
        size_t nLimitDescendantSize = params.limitdescendantsize * 1000;

        std::string errString;

        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, 
		nLimitAncestors, nLimitAncestorSize, nLimitDescendants, 
		nLimitDescendantSize, errString)) 
		{
            return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
        }

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure setConflicts and setAncestors don't
        // intersect.
        BOOST_FOREACH(CEDCTxMemPool::txiter ancestorIt, setAncestors)
        {
            const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
            if (setConflicts.count(hashAncestor))
            {
                return state.DoS(10, false,
                                 REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                                 strprintf("%s spends conflicting transaction %s",
                                           hash.ToString(),
                                           hashAncestor.ToString()));
            }
        }

        // Check if it's economically rational to mine this transaction rather
        // than the ones it replaces.
        CAmount nConflictingFees = 0;
        size_t nConflictingSize = 0;
        uint64_t nConflictingCount = 0;
        CEDCTxMemPool::setEntries allConflicting;

        // If we don't hold the lock allConflicting might be incomplete; the
        // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
        // mempool consistency for us.
        LOCK(pool.cs);
        if (setConflicts.size())
        {
            CFeeRate newFeeRate(nModifiedFees, nSize);
            set<uint256> setConflictsParents;
            const int maxDescendantsToVisit = 100;
            CEDCTxMemPool::setEntries setIterConflicting;
            BOOST_FOREACH(const uint256 &hashConflicting, setConflicts)
            {
                CEDCTxMemPool::txiter mi = pool.mapTx.find(hashConflicting);
                if (mi == pool.mapTx.end())
                    continue;

                // Save these to avoid repeated lookups
                setIterConflicting.insert(mi);

                // Don't allow the replacement to reduce the feerate of the
                // mempool.
                //
                // We usually don't want to accept replacements with lower
                // feerates than what they replaced as that would lower the
                // feerate of the next block. Requiring that the feerate always
                // be increased is also an easy-to-reason about way to prevent
                // DoS attacks via replacements.
                //
                // The mining code doesn't (currently) take children into
                // account (CPFP) so we only consider the feerates of
                // transactions being directly replaced, not their indirect
                // descendants. While that does mean high feerate children are
                // ignored when deciding whether or not to replace, we do
                // require the replacement to pay more overall fees too,
                // mitigating most cases.
                CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
                if (newFeeRate <= oldFeeRate)
                {
                    return state.DoS(0, false,
                            REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                            strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                                  hash.ToString(),
                                  newFeeRate.ToString(),
                                  oldFeeRate.ToString()));
                }

                BOOST_FOREACH(const CEDCTxIn &txin, mi->GetTx().vin)
                {
                    setConflictsParents.insert(txin.prevout.hash);
                }

                nConflictingCount += mi->GetCountWithDescendants();
            }

            // This potentially overestimates the number of actual descendants
            // but we just want to be conservative to avoid doing too much
            // work.
            if (nConflictingCount <= maxDescendantsToVisit) 
			{
                // If not too many to replace, then calculate the set of
                // transactions that would have to be evicted
                BOOST_FOREACH(CEDCTxMemPool::txiter it, setIterConflicting) 
				{
                    pool.CalculateDescendants(it, allConflicting);
                }
                BOOST_FOREACH(CEDCTxMemPool::txiter it, allConflicting) 
				{
                    nConflictingFees += it->GetModifiedFee();
                    nConflictingSize += it->GetTxSize();
                }
            } 
			else 
			{
                return state.DoS(0, false,
                        REJECT_NONSTANDARD, "too many potential replacements", false,
                        strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                            hash.ToString(),
                            nConflictingCount,
                            maxDescendantsToVisit));
            }

            for (unsigned int j = 0; j < tx.vin.size(); j++)
            {
                // We don't want to accept replacements that require low
                // feerate junk to be mined first. Ideally we'd keep track of
                // the ancestor feerates and make the decision based on that,
                // but for now requiring all new inputs to be confirmed works.
                if (!setConflictsParents.count(tx.vin[j].prevout.hash))
                {
                    // Rather than check the UTXO set - potentially expensive -
                    // it's cheaper to just check if the new input refers to a
                    // tx that's in the mempool.
                    if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
                        return state.DoS(0, false,
                                         REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                                         strprintf("replacement %s adds unconfirmed input, idx %d",
                                                  hash.ToString(), j));
                }
            }

            // The replacement must pay greater fees than the transactions it
            // replaces - if we did the bandwidth used by those conflicting
            // transactions would not be paid for.
            if (nModifiedFees < nConflictingFees)
            {
                return state.DoS(0, false,
                                 REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                 strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                                          hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
            }

            // Finally in addition to paying more fees than the conflicts the
            // new transaction must pay for its own bandwidth.
            CAmount nDeltaFees = nModifiedFees - nConflictingFees;
            if (nDeltaFees < theApp.minRelayTxFee().GetFee(nSize))
            {
                return state.DoS(0, false,
                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                        strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                              hash.ToString(),
                              FormatMoney(nDeltaFees),
                              FormatMoney(theApp.minRelayTxFee().GetFee(nSize))));
            }
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!CheckInputs(tx, state, view, true, STANDARD_SCRIPT_VERIFY_FLAGS, true))
            return false; // state filled in by CheckInputs

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true))
        {
            return edcError("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s, %s",
                __func__, hash.ToString(), FormatStateMessage(state));
        }

        // Remove conflicting transactions from the mempool
        BOOST_FOREACH(const CEDCTxMemPool::txiter it, allConflicting)
        {
            edcLogPrint("mempool", "replacing tx %s with %s for %s BTC additional fees, %d delta bytes\n",
                    it->GetTx().GetHash().ToString(),
                    hash.ToString(),
                    FormatMoney(nModifiedFees - nConflictingFees),
                    (int)nSize - (int)nConflictingSize);
        }
        pool.RemoveStaged(allConflicting, false);

        // Store transaction in memory
        pool.addUnchecked(hash, entry, setAncestors, !edcIsInitialBlockDownload());

        // trim mempool and check if tx was trimmed
        if (!fOverrideMempoolLimit) 
		{
            LimitMempoolSize(pool, params.maxmempool * 1000000, 
				params.mempoolexpiry * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }
    }

    SyncWithWallets(tx, NULL, NULL);

    return true;
}

FILE* edcOpenDiskFile(
	const CDiskBlockPos & pos, 
			 const char * prefix, 
					 bool fReadOnly )
{
    if (pos.IsNull())
        return NULL;

    boost::filesystem::path path = edcGetBlockPosFilename(pos, prefix);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");

    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");

    if (!file) 
	{
        edcLogPrintf("Unable to open file %s\n", path.string());
        return NULL;
    }
    if (pos.nPos) 
	{
        if (fseek(file, pos.nPos, SEEK_SET)) 
		{
            edcLogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* edcOpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly ) 
{
    return edcOpenDiskFile(pos, "blk", fReadOnly);
}

FILE* edcOpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false ) 
{
    return edcOpenDiskFile(pos, "rev", fReadOnly);
}

bool AcceptToMemoryPool(
			CEDCTxMemPool & pool, 
		 CValidationState & state, 
	const CEDCTransaction & tx, 
					   bool fLimitFree,
    				 bool * pfMissingInputs, 
					   bool fOverrideMempoolLimit, 
			  const CAmount nAbsurdFee)
{
	EDCapp & theApp = EDCapp::singleton();

    std::vector<uint256> vHashTxToUncache;
    bool res = AcceptToMemoryPoolWorker(pool, state, tx, fLimitFree, pfMissingInputs, fOverrideMempoolLimit, nAbsurdFee, vHashTxToUncache);

    if (!res) 
	{
        BOOST_FOREACH(const uint256& hashTx, vHashTxToUncache)
            theApp.coinsTip()->Uncache(hashTx);
    }
    return res;
}

/** Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock */
bool GetTransaction(
			  const uint256 & hash, 
			CEDCTransaction & txOut, 
	const Consensus::Params & consensusParams, 
					uint256 & hashBlock, 
						 bool fAllowSlow)
{
    CBlockIndex *pindexSlow = NULL;

    LOCK(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();
    if (theApp.mempool().lookup(hash, txOut))
    {
        return true;
    }

    if ( theApp.txIndex() ) 
	{
        CDiskTxPos postx;
        if ( theApp.blocktree()->ReadTxIndex(hash, postx)) 
		{
            CAutoFile file(edcOpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull())
                return edcError("%s: edcOpenBlockFile failed", __func__);
            CBlockHeader header;

            try 
			{
                file >> header;
                fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                file >> txOut;
            } 
			catch (const std::exception& e) 
			{
                return edcError("%s: Deserialize or I/O error - %s", __func__, e.what());
            }
            hashBlock = header.GetHash();
            if (txOut.GetHash() != hash)
                return edcError("%s: txid mismatch", __func__);
            return true;
        }
    }

    if (fAllowSlow) 
	{ 
		// use coin database to locate block that contains transaction, and 
		// scan it
        int nHeight = -1;
        {
            const CEDCCoinsViewCache &view = *theApp.coinsTip();
            const CEDCCoins* coins = view.AccessCoins(hash);
            if (coins)
                nHeight = coins->nHeight;
        }
        if (nHeight > 0)
            pindexSlow = theApp.chainActive()[nHeight];
    }

    if (pindexSlow) 
	{
        CEDCBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) 
		{
            BOOST_FOREACH(const CEDCTransaction &tx, block.vtx) 
			{
                if (tx.GetHash() == hash) 
				{
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}

//////////////////////////////////////////////////////////////////////////////
//
// CEDCBlock and CBlockIndex
//

bool WriteBlockToDisk(
							const CEDCBlock & block, 
							  CDiskBlockPos & pos, 
	const CMessageHeader::MessageStartChars & messageStart)
{
    // Open history file to append
    CAutoFile fileout(edcOpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return edcError("WriteBlockToDisk: edcOpenBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return edcError("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(
				  CEDCBlock & block, 
		const CDiskBlockPos & pos, 
	const Consensus::Params & consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(edcOpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return edcError("ReadBlockFromDisk: edcOpenBlockFile failed for %s", pos.ToString());

    // Read block
    try 
	{
        filein >> block;
    }
    catch (const std::exception& e) 
	{
        return edcError("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (!CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return edcError("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}

bool ReadBlockFromDisk(
				  CEDCBlock & block, 
		  const CBlockIndex * pindex, 
	const Consensus::Params & consensusParams)
{
    if (!ReadBlockFromDisk(block, pindex->GetBlockPos(), consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return edcError("ReadBlockFromDisk(CEDCBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

bool edcIsInitialBlockDownload()
{
	EDCapp & theApp = EDCapp::singleton();

    const CEDCChainParams& chainParams = edcParams();
    LOCK(EDC_cs_main);
    if (theApp.importing() || theApp.reindex() )
        return true;
	EDCparams & params = EDCparams::singleton();
    if (params.checkpoints && theApp.chainActive().Height() < Checkpoints::GetTotalBlocksEstimate(chainParams.Checkpoints()))
        return true;
    static bool lockIBDState = false;
    if (lockIBDState)
        return false;
    bool state = (theApp.chainActive().Height() < theApp.indexBestHeader()->nHeight - 24 * 6 ||
            std::max(theApp.chainActive().Tip()->GetBlockTime(), theApp.indexBestHeader()->GetBlockTime()) < GetTime() - params.maxtipage );
    if (!state)
        lockIBDState = true;
    return state;
}

bool edcfLargeWorkForkFound = false;
bool edcfLargeWorkInvalidChainFound = false;
CBlockIndex *edcPindexBestForkTip = NULL, *edcpindexBestForkBase = NULL;

namespace
{
void AlertNotify(const std::string& strMessage)
{
    edcUiInterface.NotifyAlertChanged();
 	EDCparams & params = EDCparams::singleton();
    std::string strCmd = params.alertnotify;
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    boost::thread t(edcRunCommand, strCmd); // thread runs free
}
}

void edcCheckForkWarningConditions()
{
    AssertLockHeld(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();

    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before the last checkpoint)
    if (edcIsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (edcPindexBestForkTip && theApp.chainActive().Height() - edcPindexBestForkTip->nHeight >= 72)
        edcPindexBestForkTip = NULL;

    if (edcPindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > theApp.chainActive().Tip()->nChainWork + (GetBlockProof(*theApp.chainActive().Tip()) * 6)))
    {
        if (!edcfLargeWorkForkFound && edcpindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                edcpindexBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (edcPindexBestForkTip && edcpindexBestForkBase)
        {
            edcLogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   edcpindexBestForkBase->nHeight, edcpindexBestForkBase->phashBlock->ToString(),
                   edcPindexBestForkTip->nHeight, edcPindexBestForkTip->phashBlock->ToString());
            edcfLargeWorkForkFound = true;
        }
        else
        {
            edcLogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            edcfLargeWorkInvalidChainFound = true;
        }
    }
    else
    {
        edcfLargeWorkForkFound = false;
        edcfLargeWorkInvalidChainFound = false;
    }
}

void edcCheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip)
{
    AssertLockHeld(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();

    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = theApp.chainActive().Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!edcPindexBestForkTip || (edcPindexBestForkTip && pindexNewForkTip->nHeight > edcPindexBestForkTip->nHeight)) &&
            pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
            theApp.chainActive().Height() - pindexNewForkTip->nHeight < 72)
    {
        edcPindexBestForkTip = pindexNewForkTip;
        edcpindexBestForkBase = pfork;
    }

    edcCheckForkWarningConditions();
}

// Requires EDC_cs_main.
void edcMisbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
        return;

    CNodeState *state = State(pnode);
    if (state == NULL)
        return;

    state->nMisbehavior += howmuch;
 	EDCparams & params = EDCparams::singleton();
    int banscore = params.banscore;
    if (state->nMisbehavior >= banscore && state->nMisbehavior - howmuch < banscore)
    {
        edcLogPrintf("%s: %s (%d -> %d) BAN THRESHOLD EXCEEDED\n", __func__, state->name, state->nMisbehavior-howmuch, state->nMisbehavior);
        state->fShouldBan = true;
    } else
        edcLogPrintf("%s: %s (%d -> %d)\n", __func__, state->name, state->nMisbehavior-howmuch, state->nMisbehavior);
}

namespace
{
void InvalidChainFound(CBlockIndex* pindexNew)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    edcLogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindexNew->GetBlockTime()));

    CBlockIndex *tip = theApp.chainActive().Tip();
    assert (tip);

    edcLogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), theApp.chainActive().Height(), log(tip->nChainWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBlockTime()));

    edcCheckForkWarningConditions();
}

void edcInvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) 
{
    int nDoS = 0;
    if (state.IsInvalid(nDoS)) 
	{
        std::map<uint256, NodeId>::iterator it = 
			mapBlockSource.find(pindex->GetBlockHash());
        if (it != mapBlockSource.end() && State(it->second)) 
		{
            assert (state.GetRejectCode() < REJECT_INTERNAL); // Blocks are never rejected with internal reject codes
            CBlockReject reject = {(unsigned char)state.GetRejectCode(), state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), pindex->GetBlockHash()};
            State(it->second)->rejects.push_back(reject);
            if (nDoS > 0)
                edcMisbehaving(it->second, nDoS);
        }
    }
    if (!state.CorruptionPossible()) 
	{
        pindex->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}
}

void UpdateCoins(
	 const CEDCTransaction & tx, 
		CEDCCoinsViewCache & inputs, 
				CEDCTxUndo & txundo, 
						 int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) 
	{
        txundo.vprevout.reserve(tx.vin.size());
        BOOST_FOREACH(const CEDCTxIn &txin, tx.vin) 
		{
            CEDCCoinsModifier coins = inputs.ModifyCoins(txin.prevout.hash);
            unsigned nPos = txin.prevout.n;

            if (nPos >= coins->vout.size() || coins->vout[nPos].IsNull())
                assert(false);
            // mark an outpoint spent, and construct undo information
            txundo.vprevout.push_back(CEDCTxInUndo(coins->vout[nPos]));
            coins->Spend(nPos);
            if (coins->vout.size() == 0) 
			{
                CEDCTxInUndo& undo = txundo.vprevout.back();
                undo.nHeight = coins->nHeight;
                undo.fCoinBase = coins->fCoinBase;
                undo.nVersion = coins->nVersion;
            }
        }
    }
    // add outputs
    inputs.ModifyNewCoins(tx.GetHash(), tx.IsCoinBase())->FromTx(tx, nHeight);
}

void UpdateCoins(
	 const CEDCTransaction & tx, 
		CEDCCoinsViewCache & inputs, 
						 int nHeight)
{
    CEDCTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CEDCScriptCheck::operator()() 
{
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (!edcVerifyScript(scriptSig, scriptPubKey, nFlags, 
	EDCCachingTransactionSignatureChecker(ptxTo, nIn, cacheStore), &error)) 
	{
        return false;
    }
    return true;
}

int GetSpendHeight(const CEDCCoinsViewCache& inputs)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(EDC_cs_main);
    CBlockIndex* pindexPrev = theApp.mapBlockIndex().find(inputs.GetBestBlock())->second;
    return pindexPrev->nHeight + 1;
}

namespace Consensus 
{

bool CheckTxInputs(
	   const CEDCTransaction & tx, 
			CValidationState & state, 
	const CEDCCoinsViewCache & inputs, 
						   int nSpendHeight)
{
        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!inputs.HaveInputs(tx))
            return state.Invalid(false, 0, "", "Inputs unavailable");

        CAmount nValueIn = 0;
        CAmount nFees = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            const COutPoint &prevout = tx.vin[i].prevout;
            const CEDCCoins *coins = inputs.AccessCoins(prevout.hash);
            assert(coins);

            // If prev is coinbase, check that it's matured
            if (coins->IsCoinBase()) 
			{
                if (nSpendHeight - coins->nHeight < EDC_COINBASE_MATURITY)
                    return state.Invalid(false,
                        REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                        strprintf("tried to spend coinbase at depth %d", nSpendHeight - coins->nHeight));
            }

            // Check for negative or overflow input values
            nValueIn += coins->vout[prevout.n].nValue;
            if (!MoneyRange(coins->vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");

        }

        if (nValueIn < tx.GetValueOut())
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx.GetValueOut())));

        // Tally transaction fees
        CAmount nTxFee = nValueIn - tx.GetValueOut();
        if (nTxFee < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    return true;
}
}

bool CheckInputs(
	   const CEDCTransaction & tx, 
		 	CValidationState & state, 
	const CEDCCoinsViewCache & inputs, 
						  bool fScriptChecks, 
				  unsigned int flags, 
						  bool cacheStore, 
std::vector<CEDCScriptCheck> * pvChecks)
{
    if (!tx.IsCoinBase())
    {
        if (!Consensus::CheckTxInputs(tx, state, inputs, GetSpendHeight(inputs)))
            return false;

        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks before the
        // last block chain checkpoint. Assuming the checkpoints are valid this
        // is safe because block merkle hashes are still computed and checked,
        // and any change will be caught at the next checkpoint. Of course, if
        // the checkpoint is for a chain that's invalid due to false scriptSigs
        // this optimisation would allow an invalid chain to be accepted.
        if (fScriptChecks) 
		{
            for (unsigned int i = 0; i < tx.vin.size(); i++) 
			{
                const COutPoint &prevout = tx.vin[i].prevout;
                const CEDCCoins* coins = inputs.AccessCoins(prevout.hash);
                assert(coins);

                // Verify signature
                CEDCScriptCheck check(*coins, tx, i, flags, cacheStore);
                if (pvChecks) 
				{
                    pvChecks->push_back(CEDCScriptCheck());
                    check.swap(pvChecks->back());
                } 
				else if (!check()) 
				{
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) 
					{
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CEDCScriptCheck check2(*coins, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheStore);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after a soft-fork
                    // super-majority vote has passed.
                    return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }
        }
    }

    return true;
}

namespace 
{

bool UndoWriteToDisk(
					const CEDCBlockUndo & blockundo, 
		  				  CDiskBlockPos & pos, 
		  				  const uint256 & hashBlock, 
const CMessageHeader::MessageStartChars & messageStart)
{
    // Open history file to append
    CAutoFile fileout(edcOpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return edcError("%s: edcOpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(blockundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return edcError("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(
	  CEDCBlockUndo & blockundo, 
const CDiskBlockPos & pos, 
	  const uint256 & hashBlock)
{
    // Open history file to read
    CAutoFile filein(edcOpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return edcError("%s: edcOpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    try 
	{
        filein >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) 
	{
        return edcError("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    if (hashChecksum != hasher.GetHash())
        return edcError("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage="")
{
    edcstrMiscWarning = strMessage;
    edcLogPrintf("*** %s\n", strMessage);
    edcUiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CEDCClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(
	CValidationState & state, 
   const std::string & strMessage, 
   const std::string & userMessage="")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}


/**
 * Apply the undo operation of a CEDCTxInUndo to the given chain state.
 * @param undo The undo object.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return True on success.
 */
bool ApplyTxInUndo(
	const CEDCTxInUndo & undo, 
	CEDCCoinsViewCache & view, 
	   const COutPoint & out)
{
    bool fClean = true;

    CEDCCoinsModifier coins = view.ModifyCoins(out.hash);
    if (undo.nHeight != 0) 
	{
        // undo data contains height: this is the last output of the prevout tx being spent
        if (!coins->IsPruned())
            fClean = fClean && edcError("%s: undo data overwriting existing transaction", __func__);
        coins->Clear();
        coins->fCoinBase = undo.fCoinBase;
        coins->nHeight = undo.nHeight;
        coins->nVersion = undo.nVersion;
    } 
	else 
	{
        if (coins->IsPruned())
            fClean = fClean && edcError("%s: undo data adding output to missing transaction", __func__);
    }
    if (coins->IsAvailable(out.n))
        fClean = fClean && edcError("%s: undo data overwriting existing output", __func__);
    if (coins->vout.size() < out.n+1)
        coins->vout.resize(out.n+1);
    coins->vout[out.n] = undo.txout;

    return fClean;
}

bool edcDisconnectBlock(
	 const CEDCBlock & block, 
	CValidationState & state, 
   const CBlockIndex * pindex, 
  CEDCCoinsViewCache & view, 
				bool * pfClean)
{
    assert(pindex->GetBlockHash() == view.GetBestBlock());

    if (pfClean)
        *pfClean = false;

    bool fClean = true;

    CEDCBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull())
        return edcError("DisconnectBlock(): no undo data available");
    if (!UndoReadFromDisk(blockUndo, pos, pindex->pprev->GetBlockHash()))
        return edcError("DisconnectBlock(): failure reading undo data");

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size())
        return edcError("DisconnectBlock(): block and undo data inconsistent");

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) 
	{
        const CEDCTransaction &tx = block.vtx[i];
        uint256 hash = tx.GetHash();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        {
        CEDCCoinsModifier outs = view.ModifyCoins(hash);
        outs->ClearUnspendable();

        CEDCCoins outsBlock(tx, pindex->nHeight);
        // The CEDCCoins serialization does not serialize negative numbers.
        // No network rules currently depend on the version here, so an inconsistency is harmless
        // but it must be corrected before txout nversion ever influences a network rule.
        if (outsBlock.nVersion < 0)
            outs->nVersion = outsBlock.nVersion;
        if (*outs != outsBlock)
            fClean = fClean && edcError("DisconnectBlock(): added transaction mismatch? database corrupted");

        // remove outputs
        outs->Clear();
        }

        // restore inputs
        if (i > 0) 
		{ // not coinbases
            const CEDCTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size())
                return edcError("DisconnectBlock(): transaction and undo data inconsistent");
            for (unsigned int j = tx.vin.size(); j-- > 0;) 
			{
                const COutPoint &out = tx.vin[j].prevout;
                const CEDCTxInUndo &undo = txundo.vprevout[j];
                if (!ApplyTxInUndo(undo, view, out))
                    fClean = false;
            }
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    if (pfClean) 
	{
        *pfClean = fClean;
        return true;
    }

    return fClean;
}

void FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = edcOpenBlockFile(posOld);
    if (fileOld) 
	{
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = edcOpenUndoFile(posOld);
    if (fileOld) 
	{
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

CCheckQueue<CEDCScriptCheck> scriptcheckqueue(128);
}

bool edcFindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

void edcThreadScriptCheck() 
{
    RenameThread("equibit-scriptch");
    scriptcheckqueue.Thread();
}

//
// Called periodically asynchronously; alerts if it smells like
// we're being fed a bad chain (blocks being generated much
// too slowly or too quickly).
//
void edcPartitionCheck(
						bool (* initialDownloadCheck)(), 
			 CCriticalSection & cs, 
	const CBlockIndex * const & bestHeader,
    					int64_t nPowTargetSpacing)
{
    if (bestHeader == NULL || initialDownloadCheck()) return;

    static int64_t lastAlertTime = 0;
    int64_t now = edcGetAdjustedTime();
    if (lastAlertTime > now-60*60*24) return; // Alert at most once per day

    const int SPAN_HOURS=4;
    const int SPAN_SECONDS=SPAN_HOURS*60*60;
    int BLOCKS_EXPECTED = SPAN_SECONDS / nPowTargetSpacing;

    boost::math::poisson_distribution<double> poisson(BLOCKS_EXPECTED);

    std::string strWarning;
    int64_t startTime = edcGetAdjustedTime()-SPAN_SECONDS;

    LOCK(cs);
    const CBlockIndex* i = bestHeader;
    int nBlocks = 0;
    while (i->GetBlockTime() >= startTime) 
	{
        ++nBlocks;
        i = i->pprev;
        if (i == NULL) return; // Ran out of chain, we must not be fully sync'ed
    }

    // How likely is it to find that many by chance?
    double p = boost::math::pdf(poisson, nBlocks);

    edcLogPrint("partitioncheck", "%s: Found %d blocks in the last %d hours\n", __func__, nBlocks, SPAN_HOURS);
    edcLogPrint("partitioncheck", "%s: likelihood: %g\n", __func__, p);

    // Aim for one false-positive about every fifty years of normal running:
    const int FIFTY_YEARS = 50*365*24*60*60;
    double alertThreshold = 1.0 / (FIFTY_YEARS / SPAN_SECONDS);

    if (p <= alertThreshold && nBlocks < BLOCKS_EXPECTED)
    {
        // Many fewer blocks than expected: alert!
        strWarning = strprintf(_("WARNING: check your network connection, %d blocks received in the last %d hours (%d expected)"),
                               nBlocks, SPAN_HOURS, BLOCKS_EXPECTED);
    }
    else if (p <= alertThreshold && nBlocks > BLOCKS_EXPECTED)
    {
        // Many more blocks than expected: alert!
        strWarning = strprintf(_("WARNING: abnormally high number of blocks generated, %d blocks received in the last %d hours (%d expected)"),
                               nBlocks, SPAN_HOURS, BLOCKS_EXPECTED);
    }
    if (!strWarning.empty())
    {
        edcstrMiscWarning = strWarning;
        AlertNotify(strWarning);
        lastAlertTime = now;
    }
}

// Protected by EDC_cs_main
namespace
{
VersionBitsCache versionbitscache;
}

int32_t edcComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(EDC_cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) 
	{
        ThresholdState state = VersionBitsState(pindexPrev, params, 
			(Consensus::DeploymentPos)i, versionbitscache);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) 
		{
            nVersion |= VersionBitsMask(params, (Consensus::DeploymentPos)i);
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const 
	{ return 0; }
    int64_t EndTime(const Consensus::Params& params) const 
	{ return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const 
	{ return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const 
	{ return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((edcComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

namespace
{
// Protected by EDC_cs_main
ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

int64_t nTimeCheck = 0;
int64_t nTimeForks = 0;
int64_t nTimeVerify = 0;
int64_t nTimeConnect = 0;
int64_t nTimeIndex = 0;
int64_t nTimeCallbacks = 0;
int64_t nTimeTotal = 0;

bool edcConnectBlock(
		  const CEDCBlock & block, 
		 CValidationState & state, 
			  CBlockIndex * pindex,
       CEDCCoinsViewCache & view, 
	const CEDCChainParams & chainparams, 
					   bool fJustCheck)
{
    AssertLockHeld(EDC_cs_main);

    int64_t nTimeStart = GetTimeMicros();

    // Check it again in case a previous version let a bad block in
    if (!edcCheckBlock(block, state, chainparams.GetConsensus(), edcGetAdjustedTime(), !fJustCheck, !fJustCheck))
        return edcError("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == NULL ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock) 
	{
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    bool fScriptChecks = true;
	EDCparams & params = EDCparams::singleton();
    if (params.checkpoints) 
	{
        CBlockIndex *pindexLastCheckpoint = Checkpoints::GetLastCheckpoint(chainparams.Checkpoints());
        if (pindexLastCheckpoint && pindexLastCheckpoint->GetAncestor(pindex->nHeight) == pindex) 
		{
            // This block is an ancestor of a checkpoint: disable script checks
            fScriptChecks = false;
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    edcLogPrint("bench", "    - Sanity checks: %.2fms [%.2fs]\n", 0.001 * (nTime1 - nTimeStart), nTimeCheck * 0.000001);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                          !((pindex->nHeight==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus().BIP34Hash));

    if (fEnforceBIP30) 
	{
        BOOST_FOREACH(const CEDCTransaction& tx, block.vtx) 
		{
            const CEDCCoins* coins = view.AccessCoins(tx.GetHash());
            if (coins && !coins->IsPruned())
                return state.DoS(100, edcError("ConnectBlock(): tried to overwrite transaction"),
                                 REJECT_INVALID, "bad-txns-BIP30");
        }
    }

    // BIP16 didn't become active until Apr 1 2012
    int64_t nBIP16SwitchTime = 1333238400;
    bool fStrictPayToScriptHash = (pindex->GetBlockTime() >= nBIP16SwitchTime);

    unsigned int flags = fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;

    // Start enforcing the DERSIG (BIP66) rules, for block.nVersion=3 blocks,
    // when 75% of the network has upgraded:
    if (block.nVersion >= 3 && IsSuperMajority(3, pindex->pprev, chainparams.GetConsensus().nMajorityEnforceBlockUpgrade, chainparams.GetConsensus())) 
	{
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
    // blocks, when 75% of the network has upgraded:
    if (block.nVersion >= 4 && IsSuperMajority(4, pindex->pprev, chainparams.GetConsensus().nMajorityEnforceBlockUpgrade, chainparams.GetConsensus())) 
	{
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindex->pprev, chainparams.GetConsensus(), Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) 
	{
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        nLockTimeFlags |= EDC_LOCKTIME_VERIFY_SEQUENCE;
    }

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    edcLogPrint("bench", "    - Fork checks: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeForks * 0.000001);

    CEDCBlockUndo blockundo;

	EDCapp & theApp = EDCapp::singleton();
    CCheckQueueControl<CEDCScriptCheck> control(fScriptChecks && theApp.scriptCheckThreads() ? &scriptcheckqueue : NULL);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CEDCTransaction &tx = block.vtx[i];

        nInputs += tx.vin.size();
        nSigOps += GetLegacySigOpCount(tx);
        if (nSigOps > EDC_MAX_BLOCK_SIGOPS)
            return state.DoS(100, edcError("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        if (!tx.IsCoinBase())
        {
            if (!view.HaveInputs(tx))
                return state.DoS(100, edcError("ConnectBlock(): inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) 
			{
                prevheights[j] = view.AccessCoins(tx.vin[j].prevout.hash)->nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) 
			{
                return state.DoS(100, edcError("%s: contains a non-BIP68-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            }

            if (fStrictPayToScriptHash)
            {
                // Add in sigops done by pay-to-script-hash inputs;
                // this is to prevent a "rogue miner" from creating
                // an incredibly-expensive-to-validate block.
                nSigOps += GetP2SHSigOpCount(tx, view);
                if (nSigOps > EDC_MAX_BLOCK_SIGOPS)
                    return state.DoS(100, edcError("ConnectBlock(): too many sigops"),
                                     REJECT_INVALID, "bad-blk-sigops");
            }

            nFees += view.GetValueIn(tx)-tx.GetValueOut();

            std::vector<CEDCScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, theApp.scriptCheckThreads() ? &vChecks : NULL))
                return edcError("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        CEDCTxUndo undoDummy;
        if (i > 0) 
		{
            blockundo.vtxundo.push_back(CEDCTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    edcLogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)block.vtx.size(), 0.001 * (nTime3 - nTime2), 0.001 * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * 0.000001);

    CAmount blockReward = nFees + edcGetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus());
    if (block.vtx[0].GetValueOut() > blockReward)
        return state.DoS(100,
                         edcError("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                               block.vtx[0].GetValueOut(), blockReward),
                               REJECT_INVALID, "bad-cb-amount");

    if (!control.Wait())
        return state.DoS(100, false);
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    edcLogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime4 - nTime2), nInputs <= 1 ? 0 : 0.001 * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * 0.000001);

    if (fJustCheck)
        return true;

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS))
    {
        if (pindex->GetUndoPos().IsNull()) 
		{
            CDiskBlockPos pos;
            if (!edcFindUndoPos(state, pindex->nFile, pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return edcError("ConnectBlock(): edcFindUndoPos failed");
            if (!UndoWriteToDisk(blockundo, pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (theApp.txIndex())
        if (!theApp.blocktree()->WriteTxIndex(vPos))
            return AbortNode(state, "Failed to write transaction index");

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    edcLogPrint("bench", "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeIndex * 0.000001);

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase;
    edcGetMainSignals().UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = block.vtx[0].GetHash();

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    edcLogPrint("bench", "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5), nTimeCallbacks * 0.000001);

    return true;
}

enum FlushStateMode 
{
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool FlushStateToDisk(CValidationState &state, FlushStateMode mode) 
{
    const CEDCChainParams & chainparams = edcParams();

    LOCK2(EDC_cs_main, cs_LastBlockFile);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
	EDCapp & theApp = EDCapp::singleton();

    try 
	{
		if (theApp.pruneMode() && fCheckForPruning && !theApp.reindex() ) 
		{
        	edcFindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
        	fCheckForPruning = false;
        	if (!setFilesToPrune.empty()) 
			{
            	fFlushForPrune = true;
            	if (!theApp.havePruned()) 
				{
                	theApp.blocktree()->WriteFlag("prunedblockfiles", true);
                	theApp.havePruned( true );
            	}
        	}
    	}

    	int64_t nNow = GetTimeMicros();
    	// Avoid writing/flushing immediately after startup.
    	if (nLastWrite == 0) 
		{
	        nLastWrite = nNow;
    	}
    	if (nLastFlush == 0) 
		{
        	nLastFlush = nNow;
    	}
    	if (nLastSetChain == 0) 
		{
        	nLastSetChain = nNow;
    	}

    	size_t cacheSize = theApp.coinsTip()->DynamicMemoryUsage();
    	// The cache is large and close to the limit, but we have time now (not in the middle of a block processing).
    	bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize * (10.0/9) > theApp.coinCacheUsage();
    	// The cache is over the limit, we have to write now.
    	bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > theApp.coinCacheUsage();
    	// It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
    	bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
    	// It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
    	bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
    	// Combine all conditions that result in a full cache flush.
    	bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
    	// Write blocks and block index to disk.
    	if (fDoFullFlush || fPeriodicWrite) 
		{
        	// Depend on nMinDiskSpace to ensure we can write block index
        	if (!CheckDiskSpace(0))
            	return state.Error("out of disk space");
        	// First make sure all block and undo data is flushed to disk.
        	FlushBlockFile();
        	// Then update all block file information (which may refer to block and undo files).
        	{
            	std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
	            vFiles.reserve(setDirtyFileInfo.size());
   	         	for (set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) 
				{
                	vFiles.push_back(make_pair(*it, &vinfoBlockFile[*it]));
                	setDirtyFileInfo.erase(it++);
            	}
            	std::vector<const CBlockIndex*> vBlocks;
            	vBlocks.reserve(setDirtyBlockIndex.size());
            	for (set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) 
				{
                	vBlocks.push_back(*it);
                	setDirtyBlockIndex.erase(it++);
            	}
            	if (!theApp.blocktree()->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) 
				{
                	return AbortNode(state, "Files to write to block index database");
            	}
        	}

        	// Finally remove any pruned files
        	if (fFlushForPrune)
            	edcUnlinkPrunedFiles(setFilesToPrune);
        	nLastWrite = nNow;
    	}

	    // Flush best chain related state. This can only be done if the blocks / block index write was also done.
    	if (fDoFullFlush) 
		{
        	// Typical CEDCCoins structures on disk are around 128 bytes in size.
        	// Pushing a new one to the database can cause it to be written
        	// twice (once in the log, and once in the tables). This is already
        	// an overestimation, as most will delete an existing entry or
        	// overwrite one. Still, use a conservative safety factor of 2.
        	if (!CheckDiskSpace(128 * 2 * 2 *theApp.coinsTip()->GetCacheSize()))
            	return state.Error("out of disk space");
        	// Flush the chainstate (which may refer to block index entries).
        	if (!theApp.coinsTip()->Flush())
            	return AbortNode(state, "Failed to write to coin database");
        	nLastFlush = nNow;
    	}

    	if (fDoFullFlush || 
		((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000)) 
		{
        	// Update best block in wallet (so we can detect restored wallets).
        	edcGetMainSignals().SetBestChain(theApp.chainActive().GetLocator());
	        nLastSetChain = nNow;
   	 	}
    } 
	catch (const std::runtime_error& e) 
	{
        return AbortNode(state, std::string("System error while flushing: ") + 
			e.what());
    }

    return true;
}
}

void edcFlushStateToDisk() 
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

void edcPruneAndFlush() 
{
    CValidationState state;
    fCheckForPruning = true;
    FlushStateToDisk(state, FLUSH_STATE_NONE);
}

namespace
{
/** Update theApp.chainActive() and related internal data structures. */
void UpdateTip(
			  CBlockIndex * pindexNew, 
	const CEDCChainParams & chainParams) 
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.chainActive().SetTip(pindexNew);

    // New best block
    edcnTimeBestReceived = GetTime();
    theApp.mempool().AddTransactionsUpdated(1);

    theApp.blockChange().notify_all();

    static bool fWarned = false;
	std::vector<std::string> warningMessages;
    if (!edcIsInitialBlockDownload())
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = theApp.chainActive().Tip();
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) 
		{
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) 
			{
                if (state == THRESHOLD_ACTIVE) 
				{
                    edcstrMiscWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                    if (!fWarned) 
					{
                        AlertNotify(edcstrMiscWarning);
                        fWarned = true;
                    }
                } 
				else 
				{
					warningMessages.push_back(strprintf("unknown new rules are about to activate (versionbit %i)", bit));
                }
            }
        }
		// Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            int32_t nExpectedVersion = edcComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
			warningMessages.push_back(strprintf("%d of last 100 blocks have unexpected version", nUpgraded));
        if (nUpgraded > 100/2)
        {
            // edcstrMiscWarning is read by edcGetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            edcstrMiscWarning = _("Warning: Unknown block versions being mined! It's possible unknown rules are in effect");
            if (!fWarned) 
			{
                AlertNotify(edcstrMiscWarning);
                fWarned = true;
            }
        }
    }
    edcLogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utx)", __func__,
      chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(), chainActive.Tip()->nVersion,
      log(chainActive.Tip()->nChainWork.getdouble())/log(2.0), (unsigned long)chainActive.Tip()->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
      Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), chainActive.Tip()), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize());
    if (!warningMessages.empty())
        edcLogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", "));
    edcLogPrintf("\n");
}

/** Disconnect chainActive's tip. You probably want to call mempool.removeForReorg and manually re-limit mempool size after this, with EDC_cs_main held. */
bool DisconnectTip(
	  	 CValidationState & state, 
	const CEDCChainParams & chainparams)
{
	EDCapp & theApp = EDCapp::singleton();

    CBlockIndex *pindexDelete = theApp.chainActive().Tip();
    assert(pindexDelete);

    // Read block from disk.
    CEDCBlock block;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()))
        return AbortNode(state, "Failed to read block");

    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CEDCCoinsViewCache view(theApp.coinsTip());
        if (!edcDisconnectBlock(block, state, pindexDelete, view))
            return edcError("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        assert(view.Flush());
    }
    edcLogPrint("bench", "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);

    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;

    // Resurrect mempool transactions from the disconnected block.
    std::vector<uint256> vHashUpdate;
    BOOST_FOREACH(const CEDCTransaction &tx, block.vtx) 
	{
        // ignore validation errors in resurrected transactions
        list<CEDCTransaction> removed;
        CValidationState stateDummy;
        if (tx.IsCoinBase() || !AcceptToMemoryPool(theApp.mempool(), stateDummy, tx, false, NULL, NULL, true)) 
		{
            theApp.mempool().removeRecursive(tx, removed);
        } 
		else if (theApp.mempool().exists(tx.GetHash())) 
		{
            vHashUpdate.push_back(tx.GetHash());
        }
    }

    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in this
    // block that were added back and cleans up the mempool state.
    theApp.mempool().UpdateTransactionsFromBlock(vHashUpdate);

    // Update theApp.chainActive() and related variables.
    UpdateTip(pindexDelete->pprev, chainparams);

    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    BOOST_FOREACH(const CEDCTransaction &tx, block.vtx) 
	{
        SyncWithWallets(tx, pindexDelete->pprev, NULL);
    }
    return true;
}

int64_t nTimeReadFromDisk = 0;
int64_t nTimeConnectTotal = 0;
int64_t nTimeFlush = 0;
int64_t nTimeChainState = 0;
int64_t nTimePostConnect = 0;

/**
 * Connect a new block to theApp.chainActive(). pblock is either NULL or a pointer to a CEDCBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectTip(
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
		      CBlockIndex * pindexNew, 
	      const CEDCBlock * pblock)
{
	EDCapp & theApp = EDCapp::singleton();

    assert(pindexNew->pprev == theApp.chainActive().Tip());

    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    CEDCBlock block;
    if (!pblock) 
	{
        if (!ReadBlockFromDisk(block, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
        pblock = &block;
    }

    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    edcLogPrint("bench", "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        CEDCCoinsViewCache view(theApp.coinsTip());
        bool rv = edcConnectBlock(*pblock, state, pindexNew, view, chainparams);
        edcGetMainSignals().BlockChecked(*pblock, state);

        if (!rv) 
		{
            if (state.IsInvalid())
                edcInvalidBlockFound(pindexNew, state);
            return edcError("ConnectTip(): ConnectBlock %s failed", pindexNew->GetBlockHash().ToString());
        }
        mapBlockSource.erase(pindexNew->GetBlockHash());
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        edcLogPrint("bench", "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        assert(view.Flush());
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    edcLogPrint("bench", "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    edcLogPrint("bench", "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);
    // Remove conflicting transactions from the mempool.
    list<CEDCTransaction> txConflicted;

    theApp.mempool().removeForBlock(pblock->vtx, pindexNew->nHeight, txConflicted, !edcIsInitialBlockDownload());
    // Update theApp.chainActive() & related variables.
    UpdateTip(pindexNew, chainparams);
    // Tell wallet about transactions that went from theApp.mempool()
    // to conflicted:
    BOOST_FOREACH(const CEDCTransaction &tx, txConflicted) 
	{
        SyncWithWallets(tx, pindexNew, NULL);
    }
    // ... and about transactions that got confirmed:
    BOOST_FOREACH(const CEDCTransaction &tx, pblock->vtx) 
	{
        SyncWithWallets(tx, pindexNew, pblock);
    }

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    edcLogPrint("bench", "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    edcLogPrint("bench", "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* FindMostWorkChain() 
{
	EDCapp & theApp = EDCapp::singleton();

    do 
	{
        CBlockIndex *pindexNew = NULL;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return NULL;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !theApp.chainActive().Contains(pindexTest)) 
		{
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) 
			{
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == NULL || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) 
				{
                    if (fFailedChain) 
					{
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } 
					else if (fMissingData) 
					{
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void PruneBlockIndexCandidates() 
{
	EDCapp & theApp = EDCapp::singleton();

    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, theApp.chainActive().Tip())) 
	{
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either NULL or a pointer to a CEDCBlock corresponding to pindexMostWork.
 */
bool ActivateBestChainStep(
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
	          CBlockIndex * pindexMostWork, 
          const CEDCBlock * pblock,
					 bool & fInvalidFound )
{
	EDCapp & theApp = EDCapp::singleton();

    AssertLockHeld(EDC_cs_main);
    const CBlockIndex *pindexOldTip = theApp.chainActive().Tip();
    const CBlockIndex *pindexFork = theApp.chainActive().FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    while (theApp.chainActive().Tip() && theApp.chainActive().Tip() != pindexFork) 
	{
        if (!DisconnectTip(state, chainparams))
            return false;
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) 
	{
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) 
		{
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        BOOST_REVERSE_FOREACH(CBlockIndex *pindexConnect, vpindexToConnect) 
		{
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : NULL)) 
			{
                if (state.IsInvalid()) 
				{
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } 
				else 
				{
                    // A system error occurred (disk space, database error, ...).
                    return false;
                }
            } 
			else 
			{
                PruneBlockIndexCandidates();
                if (!pindexOldTip || 
				    theApp.chainActive().Tip()->nChainWork > pindexOldTip->nChainWork)
				{
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }


    if (fBlocksDisconnected) 
	{
        theApp.mempool().removeForReorg(theApp.coinsTip(), theApp.chainActive().Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
 		EDCparams & params = EDCparams::singleton();
        LimitMempoolSize(theApp.mempool(), params.maxmempool * 1000000, 
			params.mempoolexpiry * 60 * 60);
    }
    theApp.mempool().check(theApp.coinsTip());

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        edcCheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        edcCheckForkWarningConditions();

    return true;
}

void NotifyHeaderTip() 
{
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = NULL;
    CBlockIndex* pindexHeader = NULL;
    {
        LOCK(cs_main);
        if (!setBlockIndexCandidates.empty()) 
		{
            pindexHeader = *setBlockIndexCandidates.rbegin();
        }
        if (pindexHeader != pindexHeaderOld) 
		{
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) 
	{
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
    }
}


}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either NULL or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestChain(
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
	      const CEDCBlock * pblock) 
{
	EDCapp & theApp = EDCapp::singleton();

    CBlockIndex *pindexMostWork = NULL;
    do 
	{
        boost::this_thread::interruption_point();
        if (ShutdownRequested())
            break;

        CBlockIndex *pindexNewTip = NULL;
        const CBlockIndex *pindexFork;
        bool fInitialDownload;
        {
            LOCK(EDC_cs_main);
            CBlockIndex *pindexOldTip = theApp.chainActive().Tip();
			if (pindexMostWork == NULL) 
			{
				pindexMostWork = FindMostWorkChain();
			}

            // Whether we have anything to do at all.
            if (pindexMostWork == NULL || pindexMostWork == theApp.chainActive().Tip())
                return true;

			bool fInvalidFound = false;
			if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : NULL, fInvalidFound))
                return false;

			if (fInvalidFound) 
			{
				// Wipe cache, we may need another branch now.
				pindexMostWork = NULL;
			}

            pindexNewTip = theApp.chainActive().Tip();
            pindexFork = theApp.chainActive().FindFork(pindexOldTip);
            fInitialDownload = edcIsInitialBlockDownload();
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without EDC_cs_main
        // Always notify the UI if a new block tip was connected
        if (pindexFork != pindexNewTip) 
		{
            edcUiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);

            if (!fInitialDownload) 
			{
                // Find the hashes of all blocks that weren't previously in the best chain.
                std::vector<uint256> vHashes;
                CBlockIndex *pindexToAnnounce = pindexNewTip;
                while (pindexToAnnounce != pindexFork) 
				{
                    vHashes.push_back(pindexToAnnounce->GetBlockHash());
                    pindexToAnnounce = pindexToAnnounce->pprev;
                    if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE) 
					{
                        // Limit announcements in case of a huge reorganization.
                        // Rely on the peer's synchronization mechanism in that case.
                        break;
                    }
                }
                // Relay inventory, but don't relay old inventory during initial block download.
                int nBlockEstimate = 0;
				EDCparams & params = EDCparams::singleton();
                if (params.checkpoints)
                    nBlockEstimate = Checkpoints::GetTotalBlocksEstimate(chainparams.Checkpoints());
                {
                    LOCK(theApp.vNodesCS());
                    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes()) 
					{
                        if (theApp.chainActive().Height() > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate)) 
						{
                            BOOST_REVERSE_FOREACH(const uint256& hash, vHashes)
							{
                                pnode->PushBlockHash(hash);
                            }
                        }
                    }
                }
                // Notify external listeners about the new tip.
                if (!vHashes.empty()) 
				{
                    edcGetMainSignals().UpdatedBlockTip(pindexNewTip);
                }
            }
        }
    } while(pindexMostWork != theApp.chainActive().Tip());
    edcCheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC)) 
	{
        return false;
    }

    return true;
}

bool edcInvalidateBlock(
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
	 	      CBlockIndex * pindex)
{
    AssertLockHeld(EDC_cs_main);

    // Mark the block itself as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);

	EDCapp & theApp = EDCapp::singleton();
    while (theApp.chainActive().Contains(pindex)) 
	{
        CBlockIndex *pindexWalk = theApp.chainActive().Tip();
        pindexWalk->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(pindexWalk);
        setBlockIndexCandidates.erase(pindexWalk);
        // ActivateBestChain considers blocks already in theApp.chainActive()
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, chainparams)) 
		{
            theApp.mempool().removeForReorg(theApp.coinsTip(), theApp.chainActive().Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
            return false;
        }
    }
	
 	EDCparams & params = EDCparams::singleton();
    LimitMempoolSize(theApp.mempool(), params.maxmempool * 1000000, 
		params.mempoolexpiry * 60 * 60);

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = theApp.mapBlockIndex().begin();
    while (it != theApp.mapBlockIndex().end()) 
	{
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, theApp.chainActive().Tip())) 
		{
            setBlockIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    theApp.mempool().removeForReorg(theApp.coinsTip(), theApp.chainActive().Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    return true;
}

bool edcResetBlockFailureFlags(CBlockIndex *pindex)
{
    AssertLockHeld(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = theApp.mapBlockIndex().begin();
    while (it != theApp.mapBlockIndex().end()) 
	{
        if (!it->second->IsValid() && 
		it->second->GetAncestor(nHeight) == pindex) 
		{
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && 
				it->second->nChainTx && 
				setBlockIndexCandidates.value_comp()(theApp.chainActive().Tip(), 
					it->second)) 
			{
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) 
			{
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = NULL;
            }
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != NULL) 
	{
        if (pindex->nStatus & BLOCK_FAILED_MASK) 
		{
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}

CBlockIndex* edcAddToBlockIndex(const CBlockHeader& block)
{
	EDCapp & theApp = EDCapp::singleton();

    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = theApp.mapBlockIndex().find(hash);

    if (it != theApp.mapBlockIndex().end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    assert(pindexNew);

    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = theApp.mapBlockIndex().insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = theApp.mapBlockIndex().find(block.hashPrevBlock);

    if (miPrev != theApp.mapBlockIndex().end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (theApp.indexBestHeader() == NULL || theApp.indexBestHeader()->nChainWork < pindexNew->nChainWork)
        theApp.indexBestHeader( pindexNew );

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(
	 const CEDCBlock & block, 
	CValidationState & state, 
		 CBlockIndex * pindexNew, 
 const CDiskBlockPos & pos)
{
	EDCapp & theApp = EDCapp::singleton();
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == NULL || pindexNew->pprev->nChainTx) 
	{
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) 
		{
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (theApp.chainActive().Tip() == NULL || 
			!setBlockIndexCandidates.value_comp()(pindex, theApp.chainActive().Tip())) 
			{
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, 
			std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = 
				mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) 
			{
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } 
	else 
	{
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) 
		{
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

bool edcFindUndoPos(
	CValidationState & state, 
				   int nFile, 
	   CDiskBlockPos & pos, 
		  unsigned int nAddSize)
{
	EDCapp & theApp = EDCapp::singleton();
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) 
	{
        if (theApp.pruneMode() )
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) 
		{
            FILE *file = edcOpenUndoFile(pos);
            if (file) 
			{
                edcLogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

bool edcCheckBlockHeader(
	 const CBlockHeader & block, 
	   CValidationState & state, 
const Consensus::Params & consensusParams, 
				  int64_t nAdjustedTime,
					 bool fCheckPOW = true )
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + 2 * 60 * 60)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    return true;
}

namespace
{

bool edcCheckBlock(
		const CEDCBlock & block, 
	   CValidationState & state, 
const Consensus::Params & consensusParams, 
				  int64_t nAdjustedTime,
					 bool fCheckPOW, 
					 bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.
    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!edcCheckBlockHeader(block, state, consensusParams, nAdjustedTime, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) 
	{
        bool mutated;
        uint256 hashMerkleRoot2 = edcBlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() > EDC_MAX_BLOCK_SIZE || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > EDC_MAX_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0].IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i].IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    BOOST_FOREACH(const CEDCTransaction& tx, block.vtx)
        if (!CheckTransaction(tx, state))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx.GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CEDCTransaction& tx, block.vtx)
    {
        nSigOps += GetLegacySigOpCount(tx);
    }
    if (nSigOps > EDC_MAX_BLOCK_SIGOPS)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool CheckIndexAgainstCheckpoint(
	    const CBlockIndex * pindexPrev, 
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
	        const uint256 & hash)
{
    if (*pindexPrev->phashBlock == chainparams.GetConsensus().hashGenesisBlock)
        return true;

    int nHeight = pindexPrev->nHeight+1;
    // Don't accept any forks from the main chain prior to last checkpoint
    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(chainparams.Checkpoints());
    if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        return state.DoS(100, edcError("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight));

    return true;
}

bool edcContextualCheckBlockHeader(
	 const CBlockHeader & block, 
	   CValidationState & state, 
const Consensus::Params & consensusParams,
		    CBlockIndex * const pindexPrev)
{
    // Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    for (int32_t version = 2; version < 5; ++version) // check for version 2, 3 and 4 upgrades
        if (block.nVersion < version && IsSuperMajority(version, pindexPrev, consensusParams.nMajorityRejectBlockOutdated, consensusParams))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", version - 1),
                                 strprintf("rejected nVersion=0x%08x block", version - 1));

    return true;
}

bool edcContextualCheckBlock(
	 const CEDCBlock & block, 
	CValidationState & state, 
		 CBlockIndex * const pindexPrev)
{
    const int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    const Consensus::Params& consensusParams = edcParams().GetConsensus();

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindexPrev, consensusParams, 
	Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) 
	{
        nLockTimeFlags |= EDC_LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & EDC_LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : block.GetBlockTime();

    // Check that all transactions are finalized
    BOOST_FOREACH(const CEDCTransaction& tx, block.vtx) 
	{
        if (!IsFinalTx(tx, nHeight, nLockTimeCutoff)) 
		{
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
    // if 750 of the last 1,000 blocks are version 2 or greater (51/100 if testnet):
    if (block.nVersion >= 2 && IsSuperMajority(2, pindexPrev, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0].vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0].vin[0].scriptSig.begin())) 
		{
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }

    return true;
}

bool AcceptBlockHeader(
	   const CBlockHeader & block, 
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
	         CBlockIndex ** ppindex=NULL)
{
    AssertLockHeld(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();

    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = theApp.mapBlockIndex().find(hash);
    CBlockIndex *pindex = NULL;
    if (hash != chainparams.GetConsensus().hashGenesisBlock) 
	{
        if (miSelf != theApp.mapBlockIndex().end()) 
		{
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(edcError("%s: block %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!edcCheckBlockHeader(block, state, chainparams.GetConsensus(), edcGetAdjustedTime()))
            return edcError("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        // Get prev block index
        CBlockIndex* pindexPrev = NULL;
        BlockMap::iterator mi = theApp.mapBlockIndex().find(block.hashPrevBlock);
        if (mi == theApp.mapBlockIndex().end())
            return state.DoS(10, edcError("%s: prev block not found", __func__), 0, "bad-prevblk");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, edcError("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");

        assert(pindexPrev);
		EDCparams & params = EDCparams::singleton();
        if (params.checkpoints && !CheckIndexAgainstCheckpoint(pindexPrev, state, chainparams, hash))
            return edcError("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!edcContextualCheckBlockHeader(block, state, chainparams.GetConsensus(), pindexPrev))
            return edcError("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));
    }
    if (pindex == NULL)
        pindex = edcAddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    return true;
}

/** Store block on disk. If dbp is non-NULL, the file is known to already reside on disk */
bool AcceptBlock(
          const CEDCBlock & block, 
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
	         CBlockIndex ** ppindex, 
	                   bool fRequested, 
	  const CDiskBlockPos * dbp)
{
    AssertLockHeld(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();

    CBlockIndex * pindexDummy = NULL;
    CBlockIndex * & pindex = ppindex ? *ppindex : pindexDummy;


    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (theApp.chainActive().Tip() ? pindex->nChainWork > theApp.chainActive().Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(theApp.chainActive().Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) 
		return true;

    if (!fRequested) 
	{  
		// If we didn't ask for it:
        if (pindex->nTx != 0) return true;  // This is a previously-processed block that was pruned
        if (!fHasMoreWork) return true;     // Don't process less-work chains
        if (fTooFarAhead) return true;      // Block height is too high
    }

    if ((!edcCheckBlock(block, state, chainparams.GetConsensus(), edcGetAdjustedTime() )) || 
	!edcContextualCheckBlock(block, state, pindex->pprev)) 
	{
        if (state.IsInvalid() && !state.CorruptionPossible()) 
		{
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return edcError("%s: %s", __func__, FormatStateMessage(state));
    }

    int nHeight = pindex->nHeight;

    // Write block to history file
    try 
	{
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != NULL)
            blockPos = *dbp;
        if (!edcFindBlockPos(state, blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != NULL))
            return edcError("AcceptBlock(): edcFindBlockPos failed");
        if (dbp == NULL)
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                AbortNode(state, "Failed to write block");
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
            return edcError("AcceptBlock(): ReceivedBlockTransactions failed");
    } 
	catch (const std::runtime_error& e) 
	{
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(state, FLUSH_STATE_NONE); // we just allocated more disk space for block files

    return true;
}

bool IsSuperMajority(
					  int minVersion, 
	  const CBlockIndex * pstart, 
			     unsigned nRequired, 
const Consensus::Params & consensusParams)
{
    unsigned int nFound = 0;
    for (int i = 0; i < consensusParams.nMajorityWindow && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}
}

bool ProcessNewBlock(
	     CValidationState & state, 
	const CEDCChainParams & chainparams, 
	       const CEDCNode * pfrom, 
	      const CEDCBlock * pblock, 
	                   bool fForceProcessing, 
	  const CDiskBlockPos * dbp)
{
    {
        LOCK(EDC_cs_main);
        bool fRequested = MarkBlockAsReceived(pblock->GetHash());
        fRequested |= fForceProcessing;

        // Store to disk
        CBlockIndex *pindex = NULL;
        bool ret = AcceptBlock(*pblock, state, chainparams, &pindex, fRequested, dbp);
        if (pindex && pfrom) 
		{
            mapBlockSource[pindex->GetBlockHash()] = pfrom->GetId();
        }
        edcCheckBlockIndex(chainparams.GetConsensus());
        if (!ret)
            return edcError("%s: AcceptBlock FAILED", __func__);
    }

	NotifyHeaderTip();

    if (!ActivateBestChain(state, chainparams, pblock))
        return edcError("%s: ActivateBestChain failed", __func__);

    return true;
}

bool TestBlockValidity(
	 	 CValidationState & state, 
	const CEDCChainParams & chainparams, 
		  const CEDCBlock & block, 
			  CBlockIndex * pindexPrev, 
					   bool fCheckPOW, 
					   bool fCheckMerkleRoot)
{
	EDCapp & theApp = EDCapp::singleton();

    AssertLockHeld(EDC_cs_main);
    assert(pindexPrev && pindexPrev == theApp.chainActive().Tip());
	EDCparams & params = EDCparams::singleton();
    if (params.checkpoints && !CheckIndexAgainstCheckpoint(pindexPrev, state, chainparams, block.GetHash()))
        return edcError("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

    CEDCCoinsViewCache viewNew(theApp.coinsTip());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    // NOTE: edcCheckBlockHeader is called by edcCheckBlock
    if (!edcContextualCheckBlockHeader(block, state, chainparams.GetConsensus(), pindexPrev))
        return edcError("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
    if (!edcCheckBlock(block, state, chainparams.GetConsensus(), edcGetAdjustedTime(), fCheckPOW, fCheckMerkleRoot))
        return edcError("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    if (!edcContextualCheckBlock(block, state, pindexPrev))
        return edcError("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));
    if (!edcConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Prune a block file (modify associated database entries)*/
void edcPruneOneBlockFile(const int fileNumber)
{
	EDCapp & theApp = EDCapp::singleton();

    for (BlockMap::iterator it = theApp.mapBlockIndex().begin(); it != theApp.mapBlockIndex().end(); ++it) 
	{
        CBlockIndex* pindex = it->second;
        if (pindex->nFile == fileNumber) 
		{
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) 
			{
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator it = range.first;
                range.first++;
                if (it->second == pindex) 
				{
                    mapBlocksUnlinked.erase(it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void edcUnlinkPrunedFiles(std::set<int>& setFilesToPrune)
{
    for (set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) 
	{
        CDiskBlockPos pos(*it, 0);
        boost::filesystem::remove(edcGetBlockPosFilename(pos, "blk"));
        boost::filesystem::remove(edcGetBlockPosFilename(pos, "rev"));
        edcLogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

uint64_t CalculateCurrentUsage();

/* Calculate the block/rev files that should be deleted to remain under target*/
void edcFindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(EDC_cs_main, cs_LastBlockFile);
	EDCapp & theApp = EDCapp::singleton();
    if (theApp.chainActive().Tip() == NULL || theApp.pruneTarget() == 0) 
	{
        return;
    }
    if ((uint64_t)theApp.chainActive().Tip()->nHeight <= nPruneAfterHeight) 
	{
        return;
    }

    unsigned int nLastBlockWeCanPrune = theApp.chainActive().Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= theApp.pruneTarget() ) 
	{
        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) 
		{
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < theApp.pruneTarget() )  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            edcPruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    edcLogPrint("prune", "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           theApp.pruneTarget() /1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)theApp.pruneTarget() - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

boost::filesystem::path edcGetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return edcGetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBlockIndex * edcInsertBlockIndex(uint256 hash)
{
	EDCapp & theApp = EDCapp::singleton();

    if (hash.IsNull())
        return NULL;

    // Return existing
    BlockMap::iterator mi = theApp.mapBlockIndex().find(hash);
    if (mi != theApp.mapBlockIndex().end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("edcLoadBlockIndex(): new CBlockIndex failed");
    mi = theApp.mapBlockIndex().insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

namespace
{
bool LoadBlockIndexDB()
{
    const CEDCChainParams& chainparams = edcParams();
	EDCapp & theApp = EDCapp::singleton();
    if (!theApp.blocktree()->LoadBlockIndexGuts(edcInsertBlockIndex))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(theApp.mapBlockIndex().size());
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, theApp.mapBlockIndex())
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) 
		{
            if (pindex->pprev) 
			{
                if (pindex->pprev->nChainTx) 
				{
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } 
				else 
				{
                    pindex->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } 
			else 
			{
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == NULL))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (theApp.indexBestHeader() == NULL || CBlockIndexWorkComparator()(theApp.indexBestHeader(), pindex)))
            theApp.indexBestHeader( pindex );
    }

    // Load block file info
    theApp.blocktree()->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    edcLogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) 
	{
        theApp.blocktree()->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    edcLogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) 
	{
        CBlockFileInfo info;
        if (theApp.blocktree()->ReadBlockFileInfo(nFile, info)) 
		{
            vinfoBlockFile.push_back(info);
        } 
		else 
		{
            break;
        }
    }

    // Check presence of blk files
    edcLogPrintf("Checking all blk files are present...\n");
    set<int> setBlkDataFiles;
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, theApp.mapBlockIndex())
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) 
		{
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(edcOpenBlockFile(pos, true), SER_DISK, 
		CLIENT_VERSION).IsNull()) 
		{
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
	bool flag = theApp.havePruned();
    theApp.blocktree()->ReadFlag("prunedblockfiles", flag);
	theApp.havePruned(flag);
    if (theApp.havePruned() )
        edcLogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    theApp.blocktree()->ReadReindexing(fReindexing);
    theApp.reindex( theApp.reindex() | fReindexing );

    // Check whether we have a transaction index
	flag = theApp.txIndex();
    theApp.blocktree()->ReadFlag("txindex", flag);
	theApp.txIndex(flag);
    edcLogPrintf("%s: transaction index %s\n", __func__, 
		theApp.txIndex() ? "enabled" : "disabled");

    // Load pointer to end of best chain
    BlockMap::iterator it = theApp.mapBlockIndex().find(theApp.coinsTip()->GetBestBlock());
    if (it == theApp.mapBlockIndex().end())
        return true;
    theApp.chainActive().SetTip(it->second);

    PruneBlockIndexCandidates();

    edcLogPrintf("%s: hashBestChain=%s height=%d date=%s progress=%f\n", __func__,
        theApp.chainActive().Tip()->GetBlockHash().ToString(), theApp.chainActive().Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", theApp.chainActive().Tip()->GetBlockTime()),
        Checkpoints::GuessVerificationProgress(chainparams.Checkpoints(), theApp.chainActive().Tip()));

    return true;
}
}

CEDCVerifyDB::CEDCVerifyDB()
{
    edcUiInterface.ShowProgress(_("Verifying blocks..."), 0);
}

CEDCVerifyDB::~CEDCVerifyDB()
{
    edcUiInterface.ShowProgress("", 100);
}

bool CEDCVerifyDB::VerifyDB(
  const CEDCChainParams & chainparams, 
	      CEDCCoinsView * coinsview, 
	       	          int nCheckLevel, 
	       	          int nCheckDepth)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(EDC_cs_main);

    if (theApp.chainActive().Tip() == NULL || theApp.chainActive().Tip()->pprev == NULL)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000

    if (nCheckDepth > theApp.chainActive().Height())
        nCheckDepth = theApp.chainActive().Height();

    nCheckLevel = std::max(0, std::min(4, nCheckLevel));

    edcLogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);

    CEDCCoinsViewCache coins(coinsview);
    CBlockIndex* pindexState = theApp.chainActive().Tip();
    CBlockIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;

    for (CBlockIndex* pindex = theApp.chainActive().Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        edcUiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 
			(int)(((double)(theApp.chainActive().Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100)))));

        if (pindex->nHeight < theApp.chainActive().Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            edcLogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }
        CEDCBlock block;

        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return edcError("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, 
				pindex->GetBlockHash().ToString());

        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !edcCheckBlock(block, state, chainparams.GetConsensus(), edcGetAdjustedTime()))
            return edcError("%s: *** found bad block at %d, hash=%s (%s)\n", __func__, 
                         pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));

        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) 
		{
            CEDCBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();

            if (!pos.IsNull()) 
			{
                if (!UndoReadFromDisk(undo, pos, pindex->pprev->GetBlockHash()))
                    return edcError("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, 
						pindex->GetBlockHash().ToString());
            }
        }

		EDCapp & theApp = EDCapp::singleton();

        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && 
		(coins.DynamicMemoryUsage() + theApp.coinsTip()->DynamicMemoryUsage()) <= theApp.coinCacheUsage() ) 
		{
            bool fClean = true;
            if (!edcDisconnectBlock(block, state, pindex, coins, &fClean))
                return edcError("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", 
					pindex->nHeight, pindex->GetBlockHash().ToString());

            pindexState = pindex->pprev;
            if (!fClean) 
			{
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } 
			else
                nGoodTransactions += block.vtx.size();
        }

        if (ShutdownRequested())
            return true;
    }

    if (pindexFailure)
        return edcError("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", 
			theApp.chainActive().Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) 
	{
        CBlockIndex *pindex = pindexState;
        while (pindex != theApp.chainActive().Tip()) 
		{
            boost::this_thread::interruption_point();
            edcUiInterface.ShowProgress(_("Verifying blocks..."), 
				std::max(1, std::min(99, 
					100 - (int)(((double)(theApp.chainActive().Height() - pindex->nHeight)) / (double)nCheckDepth * 50))));

            pindex = theApp.chainActive().Next(pindex);
            CEDCBlock block;

            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return edcError("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, 
					pindex->GetBlockHash().ToString());
            if (!edcConnectBlock(block, state, pindex, coins, chainparams))
                return edcError("VerifyDB(): *** found unconnectable block at %d, hash=%s", 
					pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }

    edcLogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", 
		theApp.chainActive().Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}

void edcUnloadBlockIndex()
{
	EDCapp & theApp = EDCapp::singleton();

    LOCK(EDC_cs_main);
    setBlockIndexCandidates.clear();
    theApp.chainActive().SetTip(NULL);
    pindexBestInvalid = NULL;
    theApp.indexBestHeader( NULL );
    theApp.mempool().clear();
    edcMapOrphanTransactions.clear();
    edcMapOrphanTransactionsByPrev.clear();
    nSyncStarted = 0;
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    nBlockSequenceId = 1;
    mapBlockSource.clear();
    mapBlocksInFlight.clear();
    nPreferredDownload = 0;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    mapNodeState.clear();
    recentRejects.reset(NULL);
    versionbitscache.Clear();

    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) 
	{
        warningcache[b].clear();
    }

    BOOST_FOREACH(BlockMap::value_type& entry, theApp.mapBlockIndex()) 
	{
        delete entry.second;
    }
    theApp.mapBlockIndex().clear();
    theApp.havePruned( false );
}

bool edcLoadBlockIndex()
{
	EDCapp & theApp = EDCapp::singleton();

    // Load block index from databases
    if (!theApp.reindex() && !LoadBlockIndexDB())
        return false;
    return true;
}

bool edcInitBlockIndex( const CEDCChainParams & chainparams ) 
{
	EDCapp & theApp = EDCapp::singleton();

    LOCK(EDC_cs_main);

    // Initialize global variables that cannot be constructed at startup.
    recentRejects.reset(new CRollingBloomFilter(120000, 0.000001));

    // Check whether we're already initialized
    if (theApp.chainActive().Genesis() != NULL)
        return true;

    // Use the provided setting for -eb_txindex in the new database
 	EDCparams & params = EDCparams::singleton();
	
    theApp.txIndex( params.txindex );
    theApp.blocktree()->WriteFlag("txindex", theApp.txIndex());
    edcLogPrintf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!theApp.reindex() ) 
	{
        try 
		{
            CEDCBlock & block = const_cast<CEDCBlock&>(chainparams.GenesisBlock());
            // Start new block file
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!edcFindBlockPos(state, blockPos, nBlockSize+8, 0, block.GetBlockTime()))
                return edcError("edcLoadBlockIndex(): edcFindBlockPos failed");
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                return edcError("edcLoadBlockIndex(): writing genesis block to disk failed");
            CBlockIndex *pindex = edcAddToBlockIndex(block);
            if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
                return edcError("edcLoadBlockIndex(): genesis block not accepted");
            if (!ActivateBestChain(state, chainparams, &block))
                return edcError("edcLoadBlockIndex(): genesis block cannot be activated");
            // Force a chainstate write so that when we VerifyDB in a moment, it doesn't check stale data
            return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
        } 
		catch (const std::runtime_error& e) 
		{
            return edcError("edcLoadBlockIndex(): failed to initialize block database: %s", e.what());
        }
    }

    return true;
}

bool edcLoadExternalBlockFile(
	const CEDCChainParams & chainparams, 
					 FILE * fileIn, 
			CDiskBlockPos * dbp)
{
	EDCapp & theApp = EDCapp::singleton();

    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try 
	{
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*EDC_MAX_BLOCK_SIZE, EDC_MAX_BLOCK_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) 
		{
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try 
			{
                // locate a header
                unsigned char buf[MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, chainparams.MessageStart(), MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > EDC_MAX_BLOCK_SIZE)
                    continue;
            } 
			catch (const std::exception&) 
			{
                // no valid block header found; don't complain
                break;
            }
            try 
			{
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                CEDCBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.GetHash();
                if (hash != chainparams.GetConsensus().hashGenesisBlock && 
				theApp.mapBlockIndex().find(block.hashPrevBlock) == 
				    theApp.mapBlockIndex().end()) 
				{
                    edcLogPrint("reindex", "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                            block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if (theApp.mapBlockIndex().count(hash) == 0 || 
				(theApp.mapBlockIndex()[hash]->nStatus & BLOCK_HAVE_DATA) == 0) 
				{
					LOCK(cs_main);
                    CValidationState state;
                    if (AcceptBlock(block, state, chainparams, NULL, true, dbp))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } 
				else if (hash != chainparams.GetConsensus().hashGenesisBlock &&
				theApp.mapBlockIndex()[hash]->nHeight % 1000 == 0) 
				{
					edcLogPrint("reindex", "Block Import: already had block %s at height %d\n", hash.ToString(), mapBlockIndex[hash]->nHeight);
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.GetConsensus().hashGenesisBlock) 
				{
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) 
					{
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) 
				{
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, 
					std::multimap<uint256, CDiskBlockPos>::iterator> range = 
						mapBlocksUnknownParent.equal_range(head);

                    while (range.first != range.second) 
					{
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        if (ReadBlockFromDisk(block, it->second, chainparams.GetConsensus()))
                        {
							edcLogPrint("reindex", "%s: Processing out of order child %s of %s\n", __func__, block.GetHash().ToString(),
                                    head.ToString());
							LOCK(cs_main);
                            CValidationState dummy;
                            if (AcceptBlock(block, dummy, chainparams, NULL, true, &it->second))
                            {
                                nLoaded++;
                                queue.push_back(block.GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
						NotifyHeaderTip();
                    }
                }
            } 
			catch (const std::exception& e) 
			{
                edcLogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } 
	catch (const std::runtime_error& e) 
	{
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        edcLogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

namespace
{

void edcCheckBlockIndex(const Consensus::Params& consensusParams)
{
	EDCapp &  theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    if (!params.checkblockindex) 
	{
        return;
    }

    LOCK(EDC_cs_main);

    // During a reindex, we read the genesis block and call edcCheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in theApp.mapBlockIndex() but no active chain.  (A few of the tests when
    // iterating the block tree require that theApp.chainActive() has been initialized.)
    if (theApp.chainActive().Height() < 0) 
	{
        assert(theApp.mapBlockIndex().size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (BlockMap::iterator it = theApp.mapBlockIndex().begin(); it != theApp.mapBlockIndex().end(); it++) 
	{
        forward.insert(std::make_pair(it->second->pprev, it->second));
    }

    assert(forward.size() == theApp.mapBlockIndex().size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(NULL);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent NULL.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = NULL; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = NULL; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = NULL; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).

    while (pindex != NULL) 
	{
        nNodes++;
        if (pindexFirstInvalid == NULL && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == NULL && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == NULL && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTreeValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTransactionsValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotChainValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotScriptsValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == NULL) 
		{
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == theApp.chainActive().Genesis()); // The current active chain's genesis block must be this block.
        }
        if (pindex->nChainTx == 0) assert(pindex->nSequenceId == 0);  // nSequenceId can't be set for blocks that aren't linked
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!theApp.havePruned()) 
		{
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } 
		else 
		{
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pindexFirstNeverProcessed != NULL) == (pindex->nChainTx == 0)); // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pindexFirstNotTransactionsValid != NULL) == (pindex->nChainTx == 0));
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == NULL || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == NULL); // All theApp.mapBlockIndex() entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == NULL); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == NULL); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == NULL); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == NULL) 
		{
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, theApp.chainActive().Tip()) && pindexFirstNeverProcessed == NULL) 
		{
            if (pindexFirstInvalid == NULL) 
			{
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  theApp.chainActive().Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == NULL || pindex == theApp.chainActive().Tip()) 
				{
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
        } 
		else 
		{ 
			// If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) 
		{
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) 
			{
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != NULL && pindexFirstInvalid == NULL) 
		{
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == NULL) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == NULL && pindexFirstMissing != NULL) 
		{
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(theApp.havePruned() ); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between theApp.chainActive() and the
            //    tip.
            // So if this block is itself better than theApp.chainActive().Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!CBlockIndexWorkComparator()(pindex, theApp.chainActive().Tip()) && setBlockIndexCandidates.count(pindex) == 0) 
			{
                if (pindexFirstInvalid == NULL) 
				{
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) 
		{
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) 
		{
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = NULL;
            if (pindex == pindexFirstMissing) pindexFirstMissing = NULL;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = NULL;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = NULL;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = NULL;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = NULL;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = NULL;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) 
			{
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) 
			{
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } 
			else 
			{
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

bool AlreadyHave(const CInv& inv) EXCLUSIVE_LOCKS_REQUIRED(EDC_cs_main)
{
	EDCapp & theApp = EDCapp::singleton();

    switch (inv.type)
    {
    case MSG_TX:
    {
        assert(recentRejects);
        if (theApp.chainActive().Tip()->GetBlockHash() != hashRecentRejectsChainTip)
        {
            // If the chain tip has changed previously rejected transactions
            // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
            // or a double-spend. Reset the rejects filter and give those
            // txs a second chance.
            hashRecentRejectsChainTip = theApp.chainActive().Tip()->GetBlockHash();
            recentRejects->reset();
        }

        // Use coinsTip->HaveCoinsInCache as a quick approximation to exclude
        // requesting or processing some txs which have already been included in a block
		EDCapp & theApp = EDCapp::singleton();
        return recentRejects->contains(inv.hash) ||
               theApp.mempool().exists(inv.hash) ||
               edcMapOrphanTransactions.count(inv.hash) ||
               theApp.coinsTip()->HaveCoinsInCache(inv.hash);
    }
    case MSG_BLOCK:
        return theApp.mapBlockIndex().count(inv.hash);
    }

    // Don't know what it is, just say we already got one
    return true;
}

void ProcessGetData(CEDCNode* pfrom, const Consensus::Params& consensusParams)
{
	EDCapp & theApp = EDCapp::singleton();

    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    LOCK(EDC_cs_main);

    while (it != pfrom->vRecvGetData.end()) 
	{
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= edcSendBufferSize())
            break;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                bool send = false;
                BlockMap::iterator mi = theApp.mapBlockIndex().find(inv.hash);
                if (mi != theApp.mapBlockIndex().end())
                {
                    if (theApp.chainActive().Contains(mi->second)) 
					{
                        send = true;
                    } 
					else 
					{
                        static const int nOneMonth = 30 * 24 * 60 * 60;
                        // To prevent fingerprinting attacks, only send blocks outside of the active
                        // chain if they are valid, and no more than a month older (both in time, and in
                        // best equivalent proof of work) than the best header chain we know about.
                        send = mi->second->IsValid(BLOCK_VALID_SCRIPTS) && (theApp.indexBestHeader() != NULL) &&
                            (theApp.indexBestHeader()->GetBlockTime() - mi->second->GetBlockTime() < nOneMonth) &&
                            (GetBlockProofEquivalentTime(*theApp.indexBestHeader(), *mi->second, *theApp.indexBestHeader(), consensusParams) < nOneMonth);
                        if (!send) 
						{
                            edcLogPrintf("%s: ignoring request from peer=%i for old block that isn't in the main chain\n", __func__, pfrom->GetId());
                        }
                    }
                }
                // disconnect node in case we have reached the outbound limit for serving historical blocks
                // never disconnect whitelisted nodes
                static const int nOneWeek = 7 * 24 * 60 * 60; // assume > 1 week = historical
                if (send && CEDCNode::OutboundTargetReached(true) && ( ((theApp.indexBestHeader() != NULL) && (theApp.indexBestHeader()->GetBlockTime() - mi->second->GetBlockTime() > nOneWeek)) || inv.type == MSG_FILTERED_BLOCK) && !pfrom->fWhitelisted)
                {
                    edcLogPrint("net", "historical block serving limit reached, disconnect peer=%d\n", pfrom->GetId());

                    //disconnect node
                    pfrom->fDisconnect = true;
                    send = false;
                }
                // Pruned nodes may have deleted the block, so check whether
                // it's available before trying to send.
                if (send && (mi->second->nStatus & BLOCK_HAVE_DATA))
                {
                    // Send block from disk
                    CEDCBlock block;
                    if (!ReadBlockFromDisk(block, (*mi).second, consensusParams))
                        assert(!"cannot load block from disk");
                    if (inv.type == MSG_BLOCK)
                        pfrom->PushMessage(NetMsgType::BLOCK, block);
                    else // MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter)
                        {
                            CEDCMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            pfrom->PushMessage(NetMsgType::MERKLEBLOCK, merkleBlock);
                            // CEDCMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didn't send here -
                            // they must either disconnect and retry or request the full block.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
                                pfrom->PushMessage(NetMsgType::TX, block.vtx[pair.first]);
                        }
                        // else
                            // no response
                    }

                    // Trigger the peer node to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, theApp.chainActive().Tip()->GetBlockHash()));
                        pfrom->PushMessage(NetMsgType::INV, vInv);
                        pfrom->hashContinue.SetNull();
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(theApp.mapRelayCS());
                    map<uint256, CEDCTransaction>::iterator mi = 
						theApp.mapRelay().find(inv.hash);
                    if (mi != theApp.mapRelay().end()) 
					{
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) 
				{
                    CEDCTransaction tx;
					EDCapp & theApp = EDCapp::singleton();
                    if (theApp.mempool().lookup(inv.hash, tx)) 
					{
                        pfrom->PushMessage(NetMsgType::TX, tx);
                        pushed = true;
                    }
                }
                if (!pushed) 
				{
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            edcGetMainSignals().Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) 
	{
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage(NetMsgType::NOTFOUND, vNotFound);
    }
}
}

CAddress edcGetLocalAddress(const CNetAddr *paddrPeer);
void edcAddTimeData(const CNetAddr& ip, int64_t nOffsetSample);

namespace
{
bool ProcessMessage(
				 CEDCNode * pfrom, 
					 string strCommand, 
			  CDataStream & vRecv, 
	                int64_t nTimeReceived, 
	const CEDCChainParams & chainparams)
{
    RandAddSeedPerfmon();
    edcLogPrint("net", "received: %s (%u bytes) peer=%d\n", SanitizeString(strCommand), vRecv.size(), pfrom->id);

 	EDCparams & params = EDCparams::singleton();

    if( params.dropmessagestest && GetRand(params.dropmessagestest) == 0)
    {
        edcLogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

	EDCapp & theApp = EDCapp::singleton();

    if (!(theApp.localServices() & NODE_BLOOM) &&
       (strCommand == NetMsgType::FILTERLOAD ||
        strCommand == NetMsgType::FILTERADD ||
        strCommand == NetMsgType::FILTERCLEAR))
    {
        if (pfrom->nVersion >= NO_BLOOM_VERSION) 
		{
			LOCK(cs_main);
            edcMisbehaving(pfrom->GetId(), 100);
            return false;
        } 
		else 
		{
            pfrom->fDisconnect = true;
            return false;
        }
    }


    if (strCommand == NetMsgType::VERSION)
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, REJECT_DUPLICATE, string("Duplicate version message"));
			LOCK(cs_main);
            edcMisbehaving(pfrom->GetId(), 1);
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            edcLogPrintf("peer=%d using obsolete version %i; disconnecting\n", pfrom->id, pfrom->nVersion);
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION));
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty()) 
		{
            vRecv >> LIMITED_STRING(pfrom->strSubVer, MAX_SUBVERSION_LENGTH);
            pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
        }
        if (!vRecv.empty()) 
		{
            vRecv >> pfrom->nStartingHeight;
        }
        {
            LOCK(pfrom->cs_filter);
            if (!vRecv.empty())
                vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
            else
                pfrom->fRelayTxes = true;
        }

        // Disconnect if we connected to ourself
        if (nNonce == theApp.localHostNonce() && nNonce > 1)
        {
            edcLogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }

        pfrom->addrLocal = addrMe;
        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            edcSeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        // Potentially mark this peer as a preferred download peer.
		{
		LOCK(cs_main);
        UpdatePreferredDownload(pfrom, State(pfrom->GetId()));
		}

        // Change version
        pfrom->PushMessage(NetMsgType::VERACK);
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
			EDCparams & params = EDCparams::singleton();
            if (params.listen && !edcIsInitialBlockDownload())
            {
                CAddress addr = edcGetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                {
                    edcLogPrintf("edcProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr);
                } 
				else if (IsPeerAddrLocalGood(pfrom)) 
				{
                    addr.SetIP(pfrom->addrLocal);
                    edcLogPrintf("edcProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || theApp.addrman().size() < 1000)
            {
                pfrom->PushMessage(NetMsgType::GETADDR);
                pfrom->fGetAddr = true;
            }
            theApp.addrman().Good(pfrom->addr);
        } 
		else 
		{
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                theApp.addrman().Add(addrFrom, addrFrom);
                theApp.addrman().Good(addrFrom);
            }
        }

        pfrom->fSuccessfullyConnected = true;

        string remoteAddr;
		EDCparams & params = EDCparams::singleton();
    	if (params.logips)
            remoteAddr = ", peeraddr=" + pfrom->addr.ToString();

        edcLogPrintf("receive version message: %s: version %d, blocks=%d, us=%s, peer=%d%s\n",
                  pfrom->cleanSubVer, pfrom->nVersion,
                  pfrom->nStartingHeight, addrMe.ToString(), pfrom->id,
                  remoteAddr);

        int64_t nTimeOffset = nTime - GetTime();
        pfrom->nTimeOffset = nTimeOffset;
        edcAddTimeData(pfrom->addr, nTimeOffset);
    }
    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
		LOCK(cs_main);
        edcMisbehaving(pfrom->GetId(), 1);
        return false;
    }
    else if (strCommand == NetMsgType::VERACK)
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        // Mark this node as currently connected, so we update its timestamp later.
        if (pfrom->fNetworkNode) 
		{
            LOCK(EDC_cs_main);
            State(pfrom->GetId())->fCurrentlyConnected = true;
        }

        if (pfrom->nVersion >= SENDHEADERS_VERSION) 
		{
            // Tell our peer we prefer to receive headers rather than inv's
            // We send this to non-NODE NETWORK peers as well, because even
            // non-NODE NETWORK peers can announce blocks (such as pruning
            // nodes)
            pfrom->PushMessage(NetMsgType::SENDHEADERS);
        }
    }
    else if (strCommand == NetMsgType::ADDR)
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && theApp.addrman().size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
			LOCK(cs_main);
            edcMisbehaving(pfrom->GetId(), 20);
            return edcError("message addr size() = %u", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64_t nNow = edcGetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = edcIsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(theApp.vNodesCS());
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the addrKnowns of the chosen nodes prevent repeats
                    static uint64_t salt0 = 0, salt1 = 0;
                    while (salt0 == 0 && salt1 == 0) 
					{
                       GetRandBytes((unsigned char*)&salt0, sizeof(salt0));
                       GetRandBytes((unsigned char*)&salt1, sizeof(salt1));
                    }
                    uint64_t hashAddr = addr.GetHash();
                    multimap<uint64_t, CEDCNode*> mapMix;
                    const CSipHasher hasher = CSipHasher(salt0, salt1).Write(hashAddr << 32).Write((GetTime() + hashAddr) / (24*60*60));
                    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
						uint64_t hashKey = CSipHasher(hasher).Write(pnode->id).Finalize();
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
					for (multimap<uint64_t, CEDCNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        theApp.addrman().Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }
    else if (strCommand == NetMsgType::SENDHEADERS)
    {
        LOCK(EDC_cs_main);
        State(pfrom->GetId())->fPreferHeaders = true;
    }
    else if (strCommand == NetMsgType::INV)
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
			LOCK(cs_main);
            edcMisbehaving(pfrom->GetId(), 20);
            return edcError("message inv size() = %u", vInv.size());
        }

        bool fBlocksOnly = params.blocksonly;

        // Allow whitelisted peers to send data other than blocks in blocks only mode if whitelistrelay is true
        if (pfrom->fWhitelisted && params.whitelistrelay )
            fBlocksOnly = false;

        LOCK(EDC_cs_main);

        std::vector<CInv> vToFetch;

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(inv);
            edcLogPrint("net", "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom->id);

            if (inv.type == MSG_BLOCK) 
			{
                UpdateBlockAvailability(pfrom->GetId(), inv.hash);
                if (!fAlreadyHave && 
					!theApp.importing() && 
					!theApp.reindex() && 
					!mapBlocksInFlight.count(inv.hash)) 
				{
                    // First request the headers preceding the announced block. In the normal fully-synced
                    // case where a new block is announced that succeeds the current tip (no reorganization),
                    // there are no such headers.
                    // Secondly, and only when we are close to being synced, we request the announced block directly,
                    // to avoid an extra round-trip. Note that we must *first* ask for the headers, so by the
                    // time the block arrives, the header chain leading up to it is already validated. Not
                    // doing this will result in the received block being rejected as an orphan in case it is
                    // not a direct successor.
                    pfrom->PushMessage(NetMsgType::GETHEADERS, theApp.chainActive().GetLocator(theApp.indexBestHeader()), inv.hash);
                    CNodeState *nodestate = State(pfrom->GetId());
                    if (CanDirectFetch(chainparams.GetConsensus()) &&
                        nodestate->nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) 
					{
                        vToFetch.push_back(inv);
                        // Mark block as in flight already, even though the actual "getdata" message only goes out
                        // later (within the same EDC_cs_main lock, though).
                        MarkBlockAsInFlight(pfrom->GetId(), inv.hash, chainparams.GetConsensus());
                    }
                    edcLogPrint("net", "getheaders (%d) %s to peer=%d\n", theApp.indexBestHeader()->nHeight, inv.hash.ToString(), pfrom->id);
                }
            }
            else
            {
                if (fBlocksOnly)
                    edcLogPrint("net", "transaction (%s) inv sent in violation of protocol peer=%d\n", inv.hash.ToString(), pfrom->id);
                else if (!fAlreadyHave && !theApp.importing() && !theApp.reindex() && !edcIsInitialBlockDownload())
                    pfrom->AskFor(inv);
            }

            // Track requests for our stuff
            edcGetMainSignals().Inventory(inv.hash);

            if (pfrom->nSendSize > (edcSendBufferSize() * 2)) 
			{
                edcMisbehaving(pfrom->GetId(), 50);
                return edcError("send buffer size() = %u", pfrom->nSendSize);
            }
        }

        if (!vToFetch.empty())
            pfrom->PushMessage(NetMsgType::GETDATA, vToFetch);
    }
    else if (strCommand == NetMsgType::GETDATA)
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
			LOCK(cs_main);
            edcMisbehaving(pfrom->GetId(), 20);
            return edcError("message getdata size() = %u", vInv.size());
        }

        if (params.debug.size() > 0 || (vInv.size() != 1))
            edcLogPrint("net", "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom->id);

        if ((params.debug.size() > 0 && vInv.size() > 0) || (vInv.size() == 1))
            edcLogPrint("net", "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom->id);

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom, chainparams.GetConsensus());
    }
    else if (strCommand == NetMsgType::GETBLOCKS)
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(EDC_cs_main);

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = edcFindForkInGlobalIndex(theApp.chainActive(), locator);

        // Send the rest of the chain
        if (pindex)
            pindex = theApp.chainActive().Next(pindex);
        int nLimit = 500;
        edcLogPrint("net", "getblocks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit, pfrom->id);
        for (; pindex; pindex = theApp.chainActive().Next(pindex))
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                edcLogPrint("net", "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            // If pruning, don't inv blocks unless we have on disk and are likely to still have
            // for some reasonable time window (1 hour) that block relay might require.
            const int nPrunedBlocksLikelyToHave = MIN_BLOCKS_TO_KEEP - 3600 / chainparams.GetConsensus().nPowTargetSpacing;
            if (theApp.pruneMode() && (!(pindex->nStatus & BLOCK_HAVE_DATA) || pindex->nHeight <= theApp.chainActive().Tip()->nHeight - nPrunedBlocksLikelyToHave))
            {
                edcLogPrint("net", " getblocks stopping, pruned or too old block at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll
                // trigger the peer to getblocks the next batch of inventory.
                edcLogPrint("net", "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }
    else if (strCommand == NetMsgType::GETHEADERS)
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(EDC_cs_main);
        if (edcIsInitialBlockDownload() && !pfrom->fWhitelisted) 
		{
            edcLogPrint("net", "Ignoring getheaders from peer=%d because node is in initial block download\n", pfrom->id);
            return true;
        }

        CNodeState *nodestate = State(pfrom->GetId());
        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            BlockMap::iterator mi = theApp.mapBlockIndex().find(hashStop);
            if (mi == theApp.mapBlockIndex().end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = edcFindForkInGlobalIndex(theApp.chainActive(), locator);
            if (pindex)
                pindex = theApp.chainActive().Next(pindex);
        }

        // we must use CEDCBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
        vector<CEDCBlock> vHeaders;
        int nLimit = MAX_HEADERS_RESULTS;
        edcLogPrint("net", "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString(), pfrom->id);
        for (; pindex; pindex = theApp.chainActive().Next(pindex))
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        // pindex can be NULL either if we sent theApp.chainActive().Tip() OR
        // if our peer has theApp.chainActive().Tip() (and thus we are sending an empty
        // headers message). In both cases it's safe to update
        // pindexBestHeaderSent to be our tip.
        nodestate->pindexBestHeaderSent = pindex ? pindex : theApp.chainActive().Tip();
        pfrom->PushMessage(NetMsgType::HEADERS, vHeaders);
    }
    else if (strCommand == NetMsgType::TX)
    {
        // Stop processing the transaction early if
        // We are in blocks only mode and peer is either not whitelisted or whitelistrelay is off
        if (params.blocksonly && 
			(!pfrom->fWhitelisted || !params.whitelistrelay))
        {
            edcLogPrint("net", "transaction sent in violation of protocol peer=%d\n", pfrom->id);
            return true;
        }

        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CEDCTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        LOCK(EDC_cs_main);

        bool fMissingInputs = false;
        CValidationState state;

        pfrom->setAskFor.erase(inv.hash);
        theApp.mapAlreadyAskedFor().erase(inv.hash);

        if (!AlreadyHave(inv) && AcceptToMemoryPool(theApp.mempool(), state, tx, true, &fMissingInputs)) 
		{
            theApp.mempool().check(theApp.coinsTip());
            RelayTransaction(tx);
            vWorkQueue.push_back(inv.hash);

            edcLogPrint("mempool", "AcceptToMemoryPool: peer=%d: accepted %s (poolsz %u txn, %u kB)\n",
                pfrom->id,
                tx.GetHash().ToString(),
                theApp.mempool().size(), theApp.mempool().DynamicMemoryUsage() / 1000);

            // Recursively process any orphan transactions that depended on this one
            set<NodeId> setMisbehaving;
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                map<uint256, set<uint256> >::iterator itByPrev = edcMapOrphanTransactionsByPrev.find(vWorkQueue[i]);
                if (itByPrev == edcMapOrphanTransactionsByPrev.end())
                    continue;
                for (set<uint256>::iterator mi = itByPrev->second.begin();
                     mi != itByPrev->second.end();
                     ++mi)
                {
                    const uint256& orphanHash = *mi;
                    const CEDCTransaction& orphanTx = edcMapOrphanTransactions[orphanHash].tx;
                    NodeId fromPeer = edcMapOrphanTransactions[orphanHash].fromPeer;
                    bool fMissingInputs2 = false;
                    // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
                    // resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
                    // anyone relaying LegitTxX banned)
                    CValidationState stateDummy;


                    if (setMisbehaving.count(fromPeer))
                        continue;
                    if (AcceptToMemoryPool(theApp.mempool(), stateDummy, orphanTx, 
					true, &fMissingInputs2)) 
					{
                        edcLogPrint("mempool", "   accepted orphan tx %s\n", orphanHash.ToString());
                        RelayTransaction(orphanTx);
                        vWorkQueue.push_back(orphanHash);
                        vEraseQueue.push_back(orphanHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        int nDos = 0;
                        if (stateDummy.IsInvalid(nDos) && nDos > 0)
                        {
                            // Punish peer that gave us an invalid orphan tx
                            edcMisbehaving(fromPeer, nDos);
                            setMisbehaving.insert(fromPeer);
                            edcLogPrint("mempool", "   invalid orphan tx %s\n", orphanHash.ToString());
                        }
                        // Has inputs but not accepted to mempool
                        // Probably non-standard or insufficient fee/priority
                        edcLogPrint("mempool", "   removed orphan tx %s\n", orphanHash.ToString());
                        vEraseQueue.push_back(orphanHash);
                        assert(recentRejects);
                        recentRejects->insert(orphanHash);
                    }
                    theApp.mempool().check(theApp.coinsTip());
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx, pfrom->GetId());

            // DoS prevention: do not allow edcMapOrphanTransactions to grow unbounded
            unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, 
				params.maxorphantx );
            unsigned int nEvicted = edcLimitOrphanTxSize(nMaxOrphanTx);
            if (nEvicted > 0)
                edcLogPrint("mempool", "mapOrphan overflow, removed %u tx\n", nEvicted);
        } 
		else 
		{
            assert(recentRejects);
            recentRejects->insert(tx.GetHash());

            if (pfrom->fWhitelisted && params.whitelistforcerelay ) 
			{
                // Always relay transactions received from whitelisted peers, even
                // if they were already in the mempool or rejected from it due
                // to policy, allowing the node to function as a gateway for
                // nodes hidden behind it.
                //
                // Never relay transactions that we would assign a non-zero DoS
                // score for, as we expect peers to do the same with us in that
                // case.
                int nDoS = 0;
                if (!state.IsInvalid(nDoS) || nDoS == 0) 
				{
                    edcLogPrintf("Force relaying tx %s from whitelisted peer=%d\n", tx.GetHash().ToString(), pfrom->id);
                    RelayTransaction(tx);
                } 
				else 
				{
                    edcLogPrintf("Not relaying invalid transaction %s from whitelisted peer=%d (%s)\n", tx.GetHash().ToString(), pfrom->id, FormatStateMessage(state));
                }
            }
        }
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            edcLogPrint("mempoolrej", "%s from peer=%d was not accepted: %s\n", tx.GetHash().ToString(),
                pfrom->id,
                FormatStateMessage(state));
            if (state.GetRejectCode() < REJECT_INTERNAL) // Never send AcceptToMemoryPool's internal codes over P2P
                pfrom->PushMessage(NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                                   state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash);
            if (nDoS > 0)
                edcMisbehaving(pfrom->GetId(), nDoS);
        }
        FlushStateToDisk(state, FLUSH_STATE_PERIODIC);
    }
    else if (strCommand == NetMsgType::HEADERS && !theApp.importing() && !theApp.reindex() ) // Ignore headers received while importing
    {
        std::vector<CBlockHeader> headers;

        // Bypass the normal CEDCBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) 
		{		
			LOCK(cs_main);
            edcMisbehaving(pfrom->GetId(), 20);
            return edcError("headers message size = %u", nCount);
        }
        headers.resize(nCount);
        for (unsigned int n = 0; n < nCount; n++) 
		{
            vRecv >> headers[n];
            ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
        }

		{
        LOCK(EDC_cs_main);

        if (nCount == 0) 
		{
            // Nothing interesting. Stop asking this peers for more headers.
            return true;
        }

        // If we already know the last header in the message, then it contains
        // no new information for us.  In this case, we do not request
        // more headers later.  This prevents multiple chains of redundant
        // getheader requests from running in parallel if triggered by incoming
        // blocks while the node is still in initial headers sync.
        const bool hasNewHeaders = (mapBlockIndex.count(headers.back().GetHash()) == 0);

        CBlockIndex *pindexLast = NULL;
        BOOST_FOREACH(const CBlockHeader& header, headers) 
		{
            CValidationState state;
            if (pindexLast != NULL && 
			header.hashPrevBlock != pindexLast->GetBlockHash()) 
			{
                edcMisbehaving(pfrom->GetId(), 20);
                return edcError("non-continuous headers sequence");
            }
            if (!AcceptBlockHeader(header, state, chainparams, &pindexLast)) 
			{
                int nDoS;
                if (state.IsInvalid(nDoS)) 
				{
                    if (nDoS > 0)
                        edcMisbehaving(pfrom->GetId(), nDoS);
                    return edcError("invalid header received");
                }
            }
        }

        if (pindexLast)
            UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());

        if (nCount == MAX_HEADERS_RESULTS && pindexLast && hasNewHeaders) 
		{
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of theApp.chainActive(). Tip 
			// or indexBestHeader, continue
            // from there instead.
            edcLogPrint("net", "more getheaders (%d) to end to peer=%d "
				"(startheight:%d)\n", pindexLast->nHeight, pfrom->id, 
				pfrom->nStartingHeight);

            pfrom->PushMessage(NetMsgType::GETHEADERS, 
				theApp.chainActive().GetLocator(pindexLast), uint256());
        }

        bool fCanDirectFetch = CanDirectFetch(chainparams.GetConsensus());
        CNodeState *nodestate = State(pfrom->GetId());
        // If this set of headers is valid and ends in a block with at least as
        // much work as our tip, download as much as possible.
        if (fCanDirectFetch && pindexLast->IsValid(BLOCK_VALID_TREE) && 
		theApp.chainActive().Tip()->nChainWork <= pindexLast->nChainWork) 
		{
            vector<CBlockIndex *> vToFetch;
            CBlockIndex *pindexWalk = pindexLast;
            // Calculate all the blocks we'd need to switch to pindexLast, up to a limit.
            while (pindexWalk && !theApp.chainActive().Contains(pindexWalk) && 
			vToFetch.size() <= MAX_BLOCKS_IN_TRANSIT_PER_PEER) 
			{
                if (!(pindexWalk->nStatus & BLOCK_HAVE_DATA) &&
                        !mapBlocksInFlight.count(pindexWalk->GetBlockHash())) 
				{
                    // We don't have this block, and it's not yet in flight.
                    vToFetch.push_back(pindexWalk);
                }
                pindexWalk = pindexWalk->pprev;
            }
            // If pindexWalk still isn't on our main chain, we're looking at a
            // very large reorg at a time we think we're close to caught up to
            // the main chain -- this shouldn't really happen.  Bail out on the
            // direct fetch and rely on parallel download instead.
            if (!theApp.chainActive().Contains(pindexWalk)) 
			{
                edcLogPrint("net", "Large reorg, won't direct fetch to %s (%d)\n",
                        pindexLast->GetBlockHash().ToString(),
                        pindexLast->nHeight);
            } 
			else 
			{
                vector<CInv> vGetData;
                // Download as much as possible, from earliest to latest.
                BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vToFetch) 
				{
                    if (nodestate->nBlocksInFlight >= 
						MAX_BLOCKS_IN_TRANSIT_PER_PEER) 
					{
                        // Can't download any more from this peer
                        break;
                    }
                    vGetData.push_back(CInv(MSG_BLOCK, pindex->GetBlockHash()));
                    MarkBlockAsInFlight(pfrom->GetId(), pindex->GetBlockHash(), chainparams.GetConsensus(), pindex);
                    edcLogPrint("net", "Requesting block %s from  peer=%d\n",
                            pindex->GetBlockHash().ToString(), pfrom->id);
                }
                if (vGetData.size() > 1) 
				{
                    edcLogPrint("net", "Downloading blocks toward %s (%d) via headers direct fetch\n",
                            pindexLast->GetBlockHash().ToString(), pindexLast->nHeight);
                }
                if (vGetData.size() > 0) 
				{
                    pfrom->PushMessage(NetMsgType::GETDATA, vGetData);
                }
            }
        }

        edcCheckBlockIndex(chainparams.GetConsensus());
		}

		NotifyHeaderTip();
    }

    else if (strCommand == NetMsgType::BLOCK && !theApp.importing() && !theApp.reindex()) // Ignore blocks received while importing
    {
        CEDCBlock block;
        vRecv >> block;

        CInv inv(MSG_BLOCK, block.GetHash());
        edcLogPrint("net", "received block %s peer=%d\n", inv.hash.ToString(), pfrom->id);

        pfrom->AddInventoryKnown(inv);

        CValidationState state;
        // Process all blocks from whitelisted peers, even if not requested,
        // unless we're still syncing with the network.
        // Such an unrequested block may still be processed, subject to the
        // conditions in AcceptBlock().
        bool forceProcessing = pfrom->fWhitelisted && !edcIsInitialBlockDownload();
        ProcessNewBlock(state, chainparams, pfrom, &block, forceProcessing, NULL);
        int nDoS;
        if (state.IsInvalid(nDoS)) 
		{
            assert (state.GetRejectCode() < REJECT_INTERNAL); // Blocks are never rejected with internal reject codes
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                               state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash);
            if (nDoS > 0) 
			{
                LOCK(EDC_cs_main);
                edcMisbehaving(pfrom->GetId(), nDoS);
            }
        }

    }
    else if (strCommand == NetMsgType::GETADDR)
    {
        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages.
        // Making nodes which are behind NAT and can only make outgoing connections ignore
        // the getaddr message mitigates the attack.
        if (!pfrom->fInbound) 
		{
            edcLogPrint("net", "Ignoring \"getaddr\" from outbound connection. peer=%d\n", pfrom->id);
            return true;
        }

        // Only send one GetAddr response per connection to reduce resource waste
        //  and discourage addr stamping of INV announcements.
        if (pfrom->fSentAddr) 
		{
            edcLogPrint("net", "Ignoring repeated \"getaddr\". peer=%d\n", pfrom->id);
            return true;
        }
        pfrom->fSentAddr = true;

        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = theApp.addrman().GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            pfrom->PushAddress(addr);
    }
    else if (strCommand == NetMsgType::MEMPOOL)
    {
        if (!(theApp.localServices() & NODE_BLOOM) && !pfrom->fWhitelisted)
        {
            edcLogPrint("net", "mempool request with bloom filters disabled, disconnect peer=%d\n", pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }

        if (CEDCNode::OutboundTargetReached(false) && !pfrom->fWhitelisted)
        {
            edcLogPrint("net", "mempool request with bandwidth limit reached, disconnect peer=%d\n", pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }
 
        LOCK(pfrom->cs_inventory);
        pfrom->fSendMempool = true;
    }
    else if (strCommand == NetMsgType::PING)
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage(NetMsgType::PONG, nonce);
        }
    }
    else if (strCommand == NetMsgType::PONG)
    {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) 
		{
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) 
			{
                if (nonce == pfrom->nPingNonceSent) 
				{
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) 
					{
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                        pfrom->nMinPingUsecTime = std::min(pfrom->nMinPingUsecTime, pingUsecTime);
                    } 
					else 
					{
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } 
				else 
				{
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) 
					{
                        // This is most likely a bug in another implementation somewhere; cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } 
			else 
			{
                sProblem = "Unsolicited pong without ping";
            }
        } 
		else 
		{
            // This is most likely a bug in another implementation somewhere; cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) 
		{
            edcLogPrint("net", "pong peer=%d: %s, %x expected, %x received, %u bytes\n",
                pfrom->id,
                sProblem,
                pfrom->nPingNonceSent,
                nonce,
                nAvail);
        }
        if (bPingFinished) 
		{
            pfrom->nPingNonceSent = 0;
        }
    }
    else if (strCommand == NetMsgType::FILTERLOAD)
    {
        CEDCBloomFilter filter;
        vRecv >> filter;

        LOCK(pfrom->cs_filter);

        if (!filter.IsWithinSizeConstraints())
		{
            // There is no excuse for sending a too-large filter
			LOCK(cs_main);
            edcMisbehaving(pfrom->GetId(), 100);
		}
        else
        {
            delete pfrom->pfilter;
            pfrom->pfilter = new CEDCBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }
    else if (strCommand == NetMsgType::FILTERADD)
    {
        vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            edcMisbehaving(pfrom->GetId(), 100);
        } 
		else 
		{
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
                pfrom->pfilter->insert(vData);
            else
			{
				LOCK(cs_main);
                edcMisbehaving(pfrom->GetId(), 100);
			}
        }
    }
    else if (strCommand == NetMsgType::FILTERCLEAR)
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CEDCBloomFilter();
        pfrom->fRelayTxes = true;
    }
    else if (strCommand == NetMsgType::REJECT)
    {
        if (params.debug.size() > 0 ) 
		{
            try 
			{
                string strMsg; unsigned char ccode; string strReason;
                vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode >> LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

                ostringstream ss;
                ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

                if (strMsg == NetMsgType::BLOCK || strMsg == NetMsgType::TX)
                {
                    uint256 hash;
                    vRecv >> hash;
                    ss << ": hash " << hash.ToString();
                }
                edcLogPrint("net", "Reject %s\n", SanitizeString(ss.str()));
            } 
			catch (const std::ios_base::failure&) 
			{
                // Avoid feedback loops by preventing reject messages from triggering a new reject message.
                edcLogPrint("net", "Unparseable reject message received\n");
            }
        }
    }
    else if (strCommand == NetMsgType::FEEFILTER) 
	{
        CAmount newFeeFilter = 0;
        vRecv >> newFeeFilter;
        if (MoneyRange(newFeeFilter)) 
		{
            {
                LOCK(pfrom->cs_feeFilter);
                pfrom->minFeeFilter = newFeeFilter;
            }
            edcLogPrint("net", "received: feefilter of %s from peer=%d\n", CFeeRate(newFeeFilter).ToString(), pfrom->id);
        }
    }
	else if( strCommand == NetMsgType::USER)
	{
		string type;
		vRecv >> type;
		CUserMessage * msg = CUserMessage::create( type, vRecv );

        edcLogPrint("net", "received: user message %s\n", msg->ToString().c_str() );
		bool isGood = msg->verify();

		if( isGood )
		{
			theApp.walletMain()->AddMessage( type, msg->GetHash(), msg );
		}
		else
		{
            edcLogPrint("net", "ERROR: message failed signature verification. Message discarded." );
		}

		delete msg;
	}
    else 
	{
        // Ignore unknown commands for extensibility
        edcLogPrint("net", "Unknown command \"%s\" from peer=%d\n", SanitizeString(strCommand), pfrom->id);
    }

    return true;
}
}

// requires LOCK(cs_vRecvMsg)
bool edcProcessMessages(CEDCNode* pfrom)
{
    const CEDCChainParams& chainparams = edcParams();
    //if (params.debug.size() > 0 )
    //    edcLogPrintf("%s(%u messages)\n", __func__, pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom, chainparams.GetConsensus());

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return fOk;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) 
	{
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= edcSendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (params.debug.size() > 0 )
        //    edcLogPrintf("%s(message %u msgsz, %u bytes, complete:%s)\n", __func__,
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, chainparams.MessageStart(), 
		MESSAGE_START_SIZE) != 0) 
		{
            edcLogPrintf("PROCESSMESSAGE: INVALID MESSAGESTART %s peer=%d\n", SanitizeString(msg.hdr.GetCommand()), pfrom->id);
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid(chainparams.MessageStart()))
        {
            edcLogPrintf("PROCESSMESSAGE: ERRORS IN HEADER %s peer=%d\n", SanitizeString(hdr.GetCommand()), pfrom->id);
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = ReadLE32((unsigned char*)&hash);
        if (nChecksum != hdr.nChecksum)
        {
            edcLogPrintf("%s(%s, %u bytes): CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", __func__,
               SanitizeString(strCommand), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime, chainparams);
            boost::this_thread::interruption_point();
        }
        catch (const std::ios_base::failure& e)
        {
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, REJECT_MALFORMED, string("error parsing message"));
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                edcLogPrintf("%s(%s, %u bytes): Exception '%s' caught, normally caused by a message being shorter than its stated length\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                edcLogPrintf("%s(%s, %u bytes): Exception '%s' caught\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else
            {
                edcPrintExceptionContinue(&e, "edcProcessMessages()");
            }
        }
        catch (const boost::thread_interrupted&) 
		{
            throw;
        }
        catch (const std::exception& e) 
		{
            edcPrintExceptionContinue(&e, "edcProcessMessages()");
        } 
		catch (...) 
		{
            edcPrintExceptionContinue(NULL, "edcProcessMessages()");
        }

        if (!fRet)
            edcLogPrintf("%s(%s, %u bytes) FAILED peer=%d\n", __func__, SanitizeString(strCommand), nMessageSize, pfrom->id);

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}

class CompareInvMempoolOrder
{
    CEDCTxMemPool *mp;
public:
    CompareInvMempoolOrder(CEDCTxMemPool *mempool)
    {
        mp = mempool;
    }

    bool operator()(std::set<uint256>::iterator a, std::set<uint256>::iterator b)
    {
        /* As std::make_heap produces a max-heap, we want the entries with the
         * fewest ancestors/highest fee to sort later. */
        return mp->CompareDepthAndScore(*b, *a);
    }
};

bool edcSendMessages(CEDCNode* pto)
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    const Consensus::Params& consensusParams = edcParams().GetConsensus();
    {
        // Don't send anything until we get its version message
        if (pto->nVersion == 0)
            return true;

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pto->fPingQueued) 
		{
            // RPC ping request by user
            pingSend = true;
        }
        if (pto->nPingNonceSent == 0 && 
		    pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros()) 
		{
            // Ping automatically sent as a latency probe & keepalive.
            pingSend = true;
        }
        if (pingSend) 
		{
            uint64_t nonce = 0;
            while (nonce == 0) 
			{
                GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
            }
            pto->fPingQueued = false;
            pto->nPingUsecStart = GetTimeMicros();
            if (pto->nVersion > BIP0031_VERSION) 
			{
                pto->nPingNonceSent = nonce;
                pto->PushMessage(NetMsgType::PING, nonce);
            } 
			else 
			{
                // Peer is too old to support ping command with nonce, pong will never arrive.
                pto->nPingNonceSent = 0;
                pto->PushMessage(NetMsgType::PING);
            }
        }

        TRY_LOCK(EDC_cs_main, lockMain); // Acquire EDC_cs_main for edcIsInitialBlockDownload() and CNodeState()
        if (!lockMain)
            return true;

        // Address refresh broadcast
        int64_t nNow = GetTimeMicros();
        if (!edcIsInitialBlockDownload() && pto->nNextLocalAddrSend < nNow) 
		{
            AdvertiseLocal(pto);
            pto->nNextLocalAddrSend = edcPoissonNextSend(nNow, AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL);
        }

        //
        // Message: addr
        //
        if (pto->nNextAddrSend < nNow) 
		{
            pto->nNextAddrSend = edcPoissonNextSend(nNow, AVG_ADDRESS_BROADCAST_INTERVAL);
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                if (!pto->addrKnown.contains(addr.GetKey()))
                {
                    pto->addrKnown.insert(addr.GetKey());
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage(NetMsgType::ADDR, vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage(NetMsgType::ADDR, vAddr);
        }

        CNodeState &state = *State(pto->GetId());
        if (state.fShouldBan) 
		{
            if (pto->fWhitelisted)
                edcLogPrintf("Warning: not punishing whitelisted peer %s!\n", 
					pto->addr.ToString());
            else 
			{
                pto->fDisconnect = true;
                if (pto->addr.IsLocal())
                    edcLogPrintf("Warning: not banning local peer %s!\n", pto->addr.ToString());
                else
                {
                    CEDCNode::Ban(pto->addr, BanReasonNodeMisbehaving);
                }
            }
            state.fShouldBan = false;
        }

        BOOST_FOREACH(const CBlockReject& reject, state.rejects)
            pto->PushMessage(NetMsgType::REJECT, (string)NetMsgType::BLOCK, reject.chRejectCode, reject.strRejectReason, reject.hashBlock);
        state.rejects.clear();

        // Start block sync
        if (theApp.indexBestHeader() == NULL)
            theApp.indexBestHeader( theApp.chainActive().Tip() );
        bool fFetch = state.fPreferredDownload || (nPreferredDownload == 0 && !pto->fClient && !pto->fOneShot); // Download if this is a nice peer, or we have no nice peers and this one might do.
        if (!state.fSyncStarted && !pto->fClient && !theApp.importing() && !theApp.reindex() ) 
		{
            // Only actively request headers from a single peer, unless we're close to today.
            if ((nSyncStarted == 0 && fFetch) || theApp.indexBestHeader()->GetBlockTime() > edcGetAdjustedTime() - 24 * 60 * 60) 
			{
                state.fSyncStarted = true;
                nSyncStarted++;
                const CBlockIndex *pindexStart = theApp.indexBestHeader();
                /* If possible, start at the block preceding the currently
                   best known header.  This ensures that we always get a
                   non-empty list of headers back as long as the peer
                   is up-to-date.  With a non-empty response, we can initialise
                   the peer's known best block.  This wouldn't be possible
                   if we requested starting at indexBestHeader and
                   got back an empty response.  */
                if (pindexStart->pprev)
                    pindexStart = pindexStart->pprev;
                edcLogPrint("net", "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, pto->id, pto->nStartingHeight);
                pto->PushMessage(NetMsgType::GETHEADERS, theApp.chainActive().GetLocator(pindexStart), uint256());
            }
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!theApp.reindex() && !theApp.importing() && !edcIsInitialBlockDownload())
        {
            edcGetMainSignals().Broadcast(edcnTimeBestReceived);
        }

        //
        // Try sending block announcements via headers
        //
        {
            // If we have less than MAX_BLOCKS_TO_ANNOUNCE in our
            // list of block hashes we're relaying, and our peer wants
            // headers announcements, then find the first header
            // not yet known to our peer but would connect, and send.
            // If no header would connect, or if we have too many
            // blocks, or if the peer doesn't want headers, just
            // add all to the inv queue.
            LOCK(pto->cs_inventory);
            vector<CEDCBlock> vHeaders;
            bool fRevertToInv = (!state.fPreferHeaders || pto->vBlockHashesToAnnounce.size() > MAX_BLOCKS_TO_ANNOUNCE);
            CBlockIndex *pBestIndex = NULL; // last header queued for delivery
            ProcessBlockAvailability(pto->id); // ensure pindexBestKnownBlock is up-to-date

            if (!fRevertToInv) 
			{
                bool fFoundStartingHeader = false;
                // Try to find first header that our peer doesn't have, and
                // then send all headers past that one.  If we come across any
                // headers that aren't on theApp.chainActive(), give up.
                BOOST_FOREACH(const uint256 &hash, pto->vBlockHashesToAnnounce)
				{
                    BlockMap::iterator mi = theApp.mapBlockIndex().find(hash);
                    assert(mi != theApp.mapBlockIndex().end());
                    CBlockIndex *pindex = mi->second;
                    if (theApp.chainActive()[pindex->nHeight] != pindex) 
					{
                        // Bail out if we reorged away from this block
                        fRevertToInv = true;
                        break;
                    }
                    if (pBestIndex != NULL && pindex->pprev != pBestIndex) 
					{
                        // This means that the list of blocks to announce don't
                        // connect to each other.
                        // This shouldn't really be possible to hit during
                        // regular operation (because reorgs should take us to
                        // a chain that has some block not on the prior chain,
                        // which should be caught by the prior check), but one
                        // way this could happen is by using invalidateblock /
                        // reconsiderblock repeatedly on the tip, causing it to
                        // be added multiple times to vBlockHashesToAnnounce.
                        // Robustly deal with this rare situation by reverting
                        // to an inv.
                        fRevertToInv = true;
                        break;
                    }

                    pBestIndex = pindex;
                    if (fFoundStartingHeader) 
					{
                        // add this to the headers message
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } 
					else if (PeerHasHeader(&state, pindex)) 
					{
                        continue; // keep looking for the first new block
                    }
					else if (pindex->pprev == NULL || PeerHasHeader(&state, pindex->pprev)) 
					{
                        // Peer doesn't have this header but they do have the prior one.
                        // Start sending headers.
                        fFoundStartingHeader = true;
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } 
					else 
					{
                        // Peer doesn't have this header or the prior one -- nothing will
                        // connect, so bail out.
                        fRevertToInv = true;
                        break;
                    }
                }
            }
            if (fRevertToInv) 
			{
                // If falling back to using an inv, just try to inv the tip.
                // The last entry in vBlockHashesToAnnounce was our tip at some point
                // in the past.
                if (!pto->vBlockHashesToAnnounce.empty()) 
				{
                    const uint256 &hashToAnnounce = pto->vBlockHashesToAnnounce.back();
                    BlockMap::iterator mi = theApp.mapBlockIndex().find(hashToAnnounce);
                    assert(mi != theApp.mapBlockIndex().end());
                    CBlockIndex *pindex = mi->second;

                    // Warn if we're announcing a block that is not on the main chain.
                    // This should be very rare and could be optimized out.
                    // Just log for now.
                    if (theApp.chainActive()[pindex->nHeight] != pindex) 
					{
                        edcLogPrint("net", "Announcing block %s not on main chain (tip=%s)\n",
                            hashToAnnounce.ToString(), theApp.chainActive().Tip()->GetBlockHash().ToString());
                    }

                    // If the peer announced this block to us, don't inv it back.
                    // (Since block announcements may not be via inv's, we can't solely rely on
                    // setInventoryKnown to track this.)
                    if (!PeerHasHeader(&state, pindex)) 
					{
                        pto->PushInventory(CInv(MSG_BLOCK, hashToAnnounce));
                        edcLogPrint("net", "%s: sending inv peer=%d hash=%s\n", __func__,
                            pto->id, hashToAnnounce.ToString());
                    }
                }
            } 
			else if (!vHeaders.empty()) 
			{
                if (vHeaders.size() > 1) 
				{
                    edcLogPrint("net", "%s: %u headers, range (%s, %s), to peer=%d\n", __func__,
                            vHeaders.size(),
                            vHeaders.front().GetHash().ToString(),
                            vHeaders.back().GetHash().ToString(), pto->id);
                } 
				else 
				{
                    edcLogPrint("net", "%s: sending header %s to peer=%d\n", __func__,
                            vHeaders.front().GetHash().ToString(), pto->id);
                }
                pto->PushMessage(NetMsgType::HEADERS, vHeaders);
                state.pindexBestHeaderSent = pBestIndex;
            }
            pto->vBlockHashesToAnnounce.clear();
        }

        //
        // Message: inventory
        //
        vector<CInv> vInv;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(std::max<size_t>(pto->vInventoryBlockToSend.size(), INVENTORY_BROADCAST_MAX));

            // Add blocks
            BOOST_FOREACH(const uint256& hash, pto->vInventoryBlockToSend) 
			{
                vInv.push_back(CInv(MSG_BLOCK, hash));
                if (vInv.size() == MAX_INV_SZ) 
				{
                    pto->PushMessage(NetMsgType::INV, vInv);
                    vInv.clear();
                }
            }
            pto->vInventoryBlockToSend.clear();

            // Check whether periodic sends should happen

            bool fSendTrickle = pto->fWhitelisted;
            if (pto->nNextInvSend < nNow) 
			{
                fSendTrickle = true;
                // Use half the delay for outbound peers, as there is less privacy concern for them.
                pto->nNextInvSend = edcPoissonNextSend(nNow, INVENTORY_BROADCAST_INTERVAL >> !pto->fInbound);
            }

            // Time to send but the peer has requested we not relay transactions.
            if (fSendTrickle) 
			{
                LOCK(pto->cs_filter);
                if (!pto->fRelayTxes) pto->setInventoryTxToSend.clear();
            }

            // Respond to BIP35 mempool requests
            if (fSendTrickle && pto->fSendMempool) 
			{
                std::vector<uint256> vtxid;
                theApp.mempool().queryHashes(vtxid);
                pto->fSendMempool = false;
                CAmount filterrate = 0;
                {
                    LOCK(pto->cs_feeFilter);
                    filterrate = pto->minFeeFilter;
                }
                LOCK(pto->cs_filter);

                BOOST_FOREACH(const uint256& hash, vtxid) 
				{
                    CInv inv(MSG_TX, hash);
                    pto->setInventoryTxToSend.erase(hash);
                    if (filterrate) 
					{
                        CFeeRate feeRate;
                        theApp.mempool().lookupFeeRate(hash, feeRate);
                        if (feeRate.GetFeePerK() < filterrate)
                            continue;
                    }
                    if (pto->pfilter) 
					{
                        CEDCTransaction tx;
						EDCapp & theApp = EDCapp::singleton();
                        bool fInMemPool = theApp.mempool().lookup(hash, tx);
                        if (!fInMemPool) continue; // another thread removed since queryHashes, maybe...
                        if (!pto->pfilter->IsRelevantAndUpdate(tx)) continue;
                    }
                    pto->filterInventoryKnown.insert(hash);
                    vInv.push_back(inv);
                    if (vInv.size() == MAX_INV_SZ) 
					{
                        pto->PushMessage(NetMsgType::INV, vInv);
                        vInv.clear();
                    }
                }
            }
            // Determine transactions to relay
            if (fSendTrickle) 
			{
                // Produce a vector with all candidates for sending
                vector<std::set<uint256>::iterator> vInvTx;
                vInvTx.reserve(pto->setInventoryTxToSend.size());
                for(std::set<uint256>::iterator it = pto->setInventoryTxToSend.begin(); 
					it != pto->setInventoryTxToSend.end(); 
					it++) 
				{
                    vInvTx.push_back(it);
                }
                CAmount filterrate = 0;

                {
                    LOCK(pto->cs_feeFilter);
                    filterrate = pto->minFeeFilter;
                }

                // Topologically and fee-rate sort the inventory we send for privacy and priority reasons.
                // A heap is used so that not all items need sorting if only a few are being sent.
				EDCapp & theApp = EDCapp::singleton();
                CompareInvMempoolOrder compareInvMempoolOrder(&theApp.mempool());
                std::make_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);

                // No reason to drain out at many times the network's capacity,
                // especially since we have many peers and some will draw much shorter delays.
                unsigned int nRelayedTransactions = 0;
                LOCK(pto->cs_filter);
                while (!vInvTx.empty() && nRelayedTransactions < INVENTORY_BROADCAST_MAX) 
				{
                    // Fetch the top element from the heap
                    std::pop_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                    std::set<uint256>::iterator it = vInvTx.back();
                    vInvTx.pop_back();
                    uint256 hash = *it;

                    // Remove it from the to-be-sent set
                    pto->setInventoryTxToSend.erase(it);

                    // Check if not in the filter already
                    if (pto->filterInventoryKnown.contains(hash)) 
					{
                        continue;
                    }
                    // Not in the mempool anymore? don't bother sending it.
                    CFeeRate feeRate;
                    if (!theApp.mempool().lookupFeeRate(hash, feeRate)) 
					{
                        continue;
                    }
                    if (filterrate && feeRate.GetFeePerK() < filterrate) 
					{
                        continue;
                    }
                    if (pto->pfilter) 
					{
                        CEDCTransaction tx;
                        if (!theApp.mempool().lookup(hash, tx)) continue;
                        if (!pto->pfilter->IsRelevantAndUpdate(tx)) continue;
                    }
                    // Send
                    vInv.push_back(CInv(MSG_TX, hash));
                    nRelayedTransactions++;
                    if (vInv.size() == MAX_INV_SZ) 
					{
                        pto->PushMessage(NetMsgType::INV, vInv);
                        vInv.clear();
                    }
                    pto->filterInventoryKnown.insert(hash);
                }
            }
        }
        if (!vInv.empty())
            pto->PushMessage(NetMsgType::INV, vInv);

        // Detect whether we're stalling
        nNow = GetTimeMicros();
        if (!pto->fDisconnect && 
		state.nStallingSince && 
		state.nStallingSince < nNow - 1000000 * BLOCK_STALLING_TIMEOUT) 
		{
            // Stalling only triggers when the block download window cannot move. During normal steady state,
            // the download window should be much larger than the to-be-downloaded set of blocks, so disconnection
            // should only happen during initial block download.
            edcLogPrintf("Peer=%d is stalling block download, disconnecting\n", pto->id);
            pto->fDisconnect = true;
        }
        // In case there is a block that has been in flight from this peer for 2 + 0.5 * N times the block interval
        // (with N the number of peers from which we're downloading validated blocks), disconnect due to timeout.
        // We compensate for other peers to prevent killing off peers due to our own downstream link
        // being saturated. We only count validated in-flight blocks so peers can't advertise non-existing block hashes
        // to unreasonably increase our timeout.
        if (!pto->fDisconnect && state.vBlocksInFlight.size() > 0) 
		{
            QueuedBlock &queuedBlock = state.vBlocksInFlight.front();
            int nOtherPeersWithValidatedDownloads = nPeersWithValidatedDownloads - (state.nBlocksInFlightValidHeaders > 0);
            if (nNow > state.nDownloadingSince + consensusParams.nPowTargetSpacing * (BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * nOtherPeersWithValidatedDownloads)) 
			{
                edcLogPrintf("Timeout downloading block %s from peer=%d, disconnecting\n", queuedBlock.hash.ToString(), pto->id);
                pto->fDisconnect = true;
            }
        }

        //
        // Message: getdata (blocks)
        //
        vector<CInv> vGetData;
        if (!pto->fDisconnect && 
		    !pto->fClient && 
		    (fFetch || !edcIsInitialBlockDownload()) && 
		    state.nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) 
		{
            vector<CBlockIndex*> vToDownload;
            NodeId staller = -1;
            FindNextBlocksToDownload(pto->GetId(), MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight, vToDownload, staller);
            BOOST_FOREACH(CBlockIndex *pindex, vToDownload) 
			{
                vGetData.push_back(CInv(MSG_BLOCK, pindex->GetBlockHash()));
                MarkBlockAsInFlight(pto->GetId(), pindex->GetBlockHash(), consensusParams, pindex);
                edcLogPrint("net", "Requesting block %s (%d) peer=%d\n", pindex->GetBlockHash().ToString(),
                    pindex->nHeight, pto->id);
            }
            if (state.nBlocksInFlight == 0 && staller != -1) 
			{
                if (State(staller)->nStallingSince == 0) 
				{
                    State(staller)->nStallingSince = nNow;
                    edcLogPrint("net", "Stall started peer=%d\n", staller);
                }
            }
        }

        //
        // Message: getdata (non-blocks)
        //
        while (!pto->fDisconnect && !pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(inv))
            {
                if (params.debug.size() > 0 )
                    edcLogPrint("net", "Requesting %s peer=%d\n", inv.ToString(), pto->id);
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage(NetMsgType::GETDATA, vGetData);
                    vGetData.clear();
                }
            } 
			else 
			{
                //If we're not going to ask, don't expect a response.
                pto->setAskFor.erase(inv.hash);
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage(NetMsgType::GETDATA, vGetData);

        //
        // Message: feefilter
        //
        // We don't want white listed peers to filter txs to us if we have -eb_whitelistforcerelay
		EDCparams & params = EDCparams::singleton();
        if (pto->nVersion >= FEEFILTER_VERSION && params.feefilter &&
            !(pto->fWhitelisted && params.whitelistforcerelay )) 
		{
			EDCapp & theApp = EDCapp::singleton();
            CAmount currentFilter = theApp.mempool().GetMinFee(params.maxmempool * 1000000).GetFeePerK();
            int64_t timeNow = GetTimeMicros();
            if (timeNow > pto->nextSendTimeFeeFilter) 
			{
                CAmount filterToSend = edcfilterRounder.round(currentFilter);
                if (filterToSend != pto->lastSentFeeFilter) 
				{
                    pto->PushMessage(NetMsgType::FEEFILTER, filterToSend);
                    pto->lastSentFeeFilter = filterToSend;
                }
                pto->nextSendTimeFeeFilter = edcPoissonNextSend(timeNow, AVG_FEEFILTER_BROADCAST_INTERVAL);
            }
            // If the fee filter has changed substantially and it's still more than MAX_FEEFILTER_CHANGE_DELAY
            // until scheduled broadcast, then move the broadcast to within MAX_FEEFILTER_CHANGE_DELAY.
            else if (timeNow + MAX_FEEFILTER_CHANGE_DELAY * 1000000 < pto->nextSendTimeFeeFilter &&
                     (currentFilter < 3 * pto->lastSentFeeFilter / 4 || currentFilter > 4 * pto->lastSentFeeFilter / 3)) 
			{
                pto->nextSendTimeFeeFilter = timeNow + (insecure_rand() % MAX_FEEFILTER_CHANGE_DELAY) * 1000000;
            }
        }

		//
		// Message: user
		//
		LOCK( pto->cs_userMessage);
		// For each message in the user message collection
		BOOST_FOREACH(CUserMessage * user, pto->vUserMessages) 
		{
			// Push the message onto the net
			if( CBroadcast * bm = dynamic_cast<CBroadcast *>(user))
			{
				pto->PushMessage( NetMsgType::USER, user->tag(), *bm );
			}
			else if( CMulticast * mm = dynamic_cast<CMulticast *>(user) )
			{
				pto->PushMessage( NetMsgType::USER, user->tag(), *mm );
			}
			else if( CPeerToPeer * ppm = dynamic_cast<CPeerToPeer *>(user) )
			{
				pto->PushMessage( NetMsgType::USER, user->tag(), *ppm );
			}
        	else
				throw runtime_error("edcSendMessage(): invalid user message type");

			delete user;
		}
		pto->vUserMessages.clear();
    }

    return true;
}

ThresholdState edcVersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
	EDCapp & theApp = EDCapp::singleton();

    LOCK(EDC_cs_main);
    return VersionBitsState(theApp.chainActive().Tip(), params, pos, versionbitscache);
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() 
	{
		EDCapp & theApp = EDCapp::singleton();

        // block headers
        BlockMap::iterator it1 = theApp.mapBlockIndex().begin();
        for (; it1 != theApp.mapBlockIndex().end(); it1++)
            delete (*it1).second;
        theApp.mapBlockIndex().clear();

        // orphan transactions
        edcMapOrphanTransactions.clear();
        edcMapOrphanTransactionsByPrev.clear();
    }
} edcinstance_of_cmaincleanup;


namespace
{

bool edcFindBlockPos(
	CValidationState & state, 
	   CDiskBlockPos & pos, 
	      unsigned int nAddSize, 
          unsigned int nHeight, 
	          uint64_t nTime, 
	              bool fKnown )
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) 
	{
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) 
	{
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) 
		{
            nFile++;
            if (vinfoBlockFile.size() <= nFile) 
			{
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) 
	{
        if (!fKnown) 
		{
            edcLogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

	EDCapp & theApp = EDCapp::singleton();
    if (!fKnown) 
	{
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + 
			BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;

        if (nNewChunks > nOldChunks) 
		{
            if (theApp.pruneMode() )
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) 
			{
                FILE *file = edcOpenBlockFile(pos);
                if (file) 
				{
                    edcLogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return state.Error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool fLargeWorkForkFound = false;
bool fLargeWorkInvalidChainFound = false;
}

std::string edcGetWarnings(const std::string& strFor)
{
	EDCparams & params = EDCparams::singleton();

    string strStatusBar;
    string strRPC;
    string strGUI;

    if (!CLIENT_VERSION_IS_RELEASE) 
	{
        strStatusBar = "This is a pre-release test build - use at your own risk - do not use for mining or merchant applications";
        strGUI = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");
    }

    if (params.testsafemode)
        strStatusBar = strRPC = strGUI = "testsafemode enabled";

    // Misc warnings like out of disk space and clock is wrong
    if (edcstrMiscWarning != "")
    {
        strStatusBar = strGUI = edcstrMiscWarning;
    }

    if (fLargeWorkForkFound)
    {
        strStatusBar = strRPC = "Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.";
        strGUI = _("Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.");
    }
    else if (fLargeWorkInvalidChainFound)
    {
        strStatusBar = strRPC = "Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.";
        strGUI = _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.");
    }

    if (strFor == "gui")
        return strGUI;
    else if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;

    assert(!"edcGetWarnings(): invalid parameter");

    return "error";
}

bool edcCheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = boost::filesystem::space(edcGetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}


