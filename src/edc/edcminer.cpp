// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/edcminer.h"

#include "amount.h"
#include "chain.h"
#include "edcchainparams.h"
#include "edc/edccoins.h"
#include "edc/consensus/edcconsensus.h"
#include "edc/consensus/edcmerkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "edc/edcmain.h"
#include "edc/edcnet.h"
#include "edc/policy/edcpolicy.h"
#include "pow.h"
#include "edc/primitives/edctransaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "edctxmempool.h"
#include "edcutil.h"
#include "utilmoneystr.h"
#include "edcvalidationinterface.h"
#include "edcapp.h"
#include "edcparams.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// EquibitMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CEDCTxMemPool::txiter a, const CEDCTxMemPool::txiter b)
    {
        return CompareEDCTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

EDCBlockAssembler::EDCBlockAssembler(const CEDCChainParams& _chainparams)
    : chainparams(_chainparams)
{
	EDCparams & params = EDCparams::singleton();

	// Largest block you're willing to create:
    nBlockMaxSize = params.blockmaxsize;

    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(EDC_MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    nBlockMinSize = params.blockminsize;
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);
}

void EDCBlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockSize = 1000;
    nBlockSigOps = 100;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;

    lastFewTxs = 0;
    blockFinished = false;
}

int64_t edcGetAdjustedTime();

CAmount edcGetBlockSubsidy(
                          int nHeight,
    const Consensus::Params & consensusParams )
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;

    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;

    // Subsidy is cut in half every 210,000 blocks which will occur
    // approximately every 4 years.
    nSubsidy >>= halvings;

// TODO: Chris wants EDC to get 1,000,000 EQB for its mining prior to opening
//       the network to customers. This function will need to be modified to
//       handle this requirement.
//       For example, if nHeight == 0, nSubsidy = 1000000.
    return nSubsidy;
}

CEDCBlockTemplate* EDCBlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn)
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    resetBlock();

    pblocktemplate.reset(new CEDCBlockTemplate());

    if(!pblocktemplate.get())
        return NULL;

    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CEDCTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    LOCK2(cs_main, theApp.mempool().cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = edcComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = params.blockversion;

    pblock->nTime = edcGetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & EDC_LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    addPriorityTxs();
    addScoreTxs();

	theApp.lastBlockTx( nBlockTx );
	theApp.lastBlockSize( nBlockSize );

    edcLogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", 
		nBlockSize, nBlockTx, nFees, nBlockSigOps);

    // Create coinbase transaction.
    CEDCMutableTransaction coinbaseTx;

    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = nFees + edcGetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

    pblock->vtx[0] = coinbaseTx;
    pblocktemplate->vTxFees[0] = -nFees;

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }

    return pblocktemplate.release();
}

bool EDCBlockAssembler::isStillDependent(CEDCTxMemPool::txiter iter)
{
	EDCapp & theApp = EDCapp::singleton();
    BOOST_FOREACH(CEDCTxMemPool::txiter parent, theApp.mempool().GetMemPoolParents(iter))
    {
        if (!inBlock.count(parent)) 
		{
            return true;
        }
    }
    return false;
}


bool EDCBlockAssembler::TestForBlock(CEDCTxMemPool::txiter iter)
{
    if (nBlockSize + iter->GetTxSize() >= nBlockMaxSize) 
	{
        // If the block is so close to full that no more txs will fit
        // or if we've tried more than 50 times to fill remaining space
        // then flag that the block is finished
        if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) 
		{
             blockFinished = true;
             return false;
        }

        // Once we're within 1000 bytes of a full block, only look at 50 more txs
        // to try to fill the remaining space.
        if (nBlockSize > nBlockMaxSize - 1000) 
		{
            lastFewTxs++;
        }
        return false;
    }

    if (nBlockSigOps + iter->GetSigOpCount() >= EDC_MAX_BLOCK_SIGOPS) 
	{
        // If the block has room for no more sig ops then
        // flag that the block is finished
        if (nBlockSigOps > EDC_MAX_BLOCK_SIGOPS - 2) 
		{
            blockFinished = true;
            return false;
        }
        // Otherwise attempt to find another tx with fewer sigops
        // to put in the block.
        return false;
    }

    // Must check that lock times are still valid
    // This can be removed once MTP is always enforced
    // as long as reorgs keep the mempool consistent.
    if (!IsFinalTx(iter->GetTx(), nHeight, nLockTimeCutoff))
        return false;

    return true;
}

void EDCBlockAssembler::AddToBlock(CEDCTxMemPool::txiter iter)
{
    pblock->vtx.push_back(iter->GetTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOps.push_back(iter->GetSigOpCount());
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += iter->GetSigOpCount();
    nFees += iter->GetFee();
    inBlock.insert(iter);

	EDCparams & params = EDCparams::singleton();
    bool fPrintPriority = params.printpriority;

	EDCapp & theApp = EDCapp::singleton();

    if (fPrintPriority) 
	{
        double dPriority = iter->GetPriority(nHeight);
        CAmount dummy;
        theApp.mempool().ApplyDeltas(iter->GetTx().GetHash(), dPriority, dummy);

        edcLogPrintf("priority %.1f fee %s txid %s\n",
                  dPriority,
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

void EDCBlockAssembler::addScoreTxs()
{
	EDCapp & theApp = EDCapp::singleton();

    std::priority_queue<CEDCTxMemPool::txiter, 
						std::vector<CEDCTxMemPool::txiter>, ScoreCompare> clearedTxs;

    CEDCTxMemPool::setEntries waitSet;
    CEDCTxMemPool::indexed_transaction_set::index<mining_score>::type::iterator mi = theApp.mempool().mapTx.get<mining_score>().begin();
    CEDCTxMemPool::txiter iter;

    while (!blockFinished && 
	(mi != theApp.mempool().mapTx.get<mining_score>().end() || !clearedTxs.empty()))
    {
        // If no txs that were previously postponed are available to try
        // again, then try the next highest score tx
        if (clearedTxs.empty()) {
            iter = theApp.mempool().mapTx.project<0>(mi);
            mi++;
        }

        // If a previously postponed tx is available to try again, then it
        // has higher score than all untried so far txs
        else 
		{
            iter = clearedTxs.top();
            clearedTxs.pop();
        }

        // If tx is dependent on other mempool txs which haven't yet been included
        // then put it in the waitSet
        if (isStillDependent(iter)) 
		{
            waitSet.insert(iter);
            continue;
        }

        // If the fee rate is below the min fee rate for mining, then we're done
        // adding txs based on score (fee rate)
        if (iter->GetModifiedFee() < ::minRelayTxFee.GetFee(iter->GetTxSize()) && 
		nBlockSize >= nBlockMinSize) 
		{
            return;
        }

        // If this tx fits in the block add it, otherwise keep looping
        if (TestForBlock(iter)) 
		{
            AddToBlock(iter);

            // This tx was successfully added, so
            // add transactions that depend on this one to the priority queue to try again
            BOOST_FOREACH(CEDCTxMemPool::txiter child, 
				theApp.mempool().GetMemPoolChildren(iter))
            {
                if (waitSet.count(child)) 
				{
                    clearedTxs.push(child);
                    waitSet.erase(child);
                }
            }
        }
    }
}

void EDCBlockAssembler::addPriorityTxs()
{
	EDCparams & params = EDCparams::singleton();

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = params.blockprioritysize;
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    if (nBlockPrioritySize == 0) 
	{
        return;
    }

	EDCapp & theApp = EDCapp::singleton();

    // This vector will be sorted into a priority queue:
    vector<EDCTxCoinAgePriority> vecPriority;
    EDCTxCoinAgePriorityCompare pricomparer;

    std::map<CEDCTxMemPool::txiter, double, CEDCTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CEDCTxMemPool::txiter, double, 
					CEDCTxMemPool::CompareIteratorByHash>::iterator waitPriIter;

    double actualPriority = -1;

    vecPriority.reserve(theApp.mempool().mapTx.size());

    for (CEDCTxMemPool::indexed_transaction_set::iterator mi = theApp.mempool().mapTx.begin();
         mi != theApp.mempool().mapTx.end(); ++mi)
    {
        double dPriority = mi->GetPriority(nHeight);
        CAmount dummy;
        theApp.mempool().ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
        vecPriority.push_back(EDCTxCoinAgePriority(dPriority, mi));
    }
    std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);

    CEDCTxMemPool::txiter iter;
    while (!vecPriority.empty() && !blockFinished) 
	{ 
		// add a tx from priority queue to fill the blockprioritysize
        iter = vecPriority.front().second;
        actualPriority = vecPriority.front().first;

        std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        vecPriority.pop_back();

        // If tx already in block, skip
        if (inBlock.count(iter)) 
		{
            assert(false); // shouldn't happen for priority txs
            continue;
        }

        // If tx is dependent on other mempool txs which haven't yet been included
        // then put it in the waitSet
        if (isStillDependent(iter)) 
		{
            waitPriMap.insert(std::make_pair(iter, actualPriority));
            continue;
        }

        // If this tx fits in the block add it, otherwise keep looping
        if (TestForBlock(iter)) 
		{
            AddToBlock(iter);

            // If now that this txs is added we've surpassed our desired priority size
            // or have dropped below the AllowFreeThreshold, then we're done adding priority txs
            if (nBlockSize + iter->GetTxSize() >= nBlockPrioritySize || 
			!AllowFree(actualPriority)) 
			{
                return;
            }

            // This tx was successfully added, so
            // add transactions that depend on this one to the priority queue to try again
            BOOST_FOREACH(CEDCTxMemPool::txiter child,theApp.mempool().GetMemPoolChildren(iter))
            {
                waitPriIter wpiter = waitPriMap.find(child);

                if (wpiter != waitPriMap.end()) 
				{
                    vecPriority.push_back(EDCTxCoinAgePriority(wpiter->second,child));
                    std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                    waitPriMap.erase(wpiter);
                }
            }
        }
    }
}

void IncrementExtraNonce(
	CEDCBlock* pblock, 
	const CBlockIndex* pindexPrev, 
	unsigned int& nExtraNonce )
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CEDCMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = edcBlockMerkleRoot(*pblock);
}
