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
// BitcoinMiner
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

extern int64_t edcGetAdjustedTime();

CEDCBlockTemplate* CreateNewEDCBlock(const CEDCChainParams& chainparams, const CScript& scriptPubKeyIn)
{
    // Create new block
    std::unique_ptr<CEDCBlockTemplate> pblocktemplate(new CEDCBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CEDCBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CEDCMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CEDCTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    EDCparams & params = EDCparams::singleton();
    unsigned int nBlockMaxSize = params.blockmaxsize;
    // Limit to between 1K and EDC_MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(EDC_MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = params.blockprioritysize;
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = params.blockminsize;
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CEDCTxMemPool::setEntries inBlock;
    CEDCTxMemPool::setEntries waitSet;

    // This vector will be sorted into a priority queue:
    vector<EDCTxCoinAgePriority> vecPriority;
    EDCTxCoinAgePriorityCompare pricomparer;
    std::map<CEDCTxMemPool::txiter, double, CEDCTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CEDCTxMemPool::txiter, double, CEDCTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    std::priority_queue<CEDCTxMemPool::txiter, std::vector<CEDCTxMemPool::txiter>, ScoreCompare> clearedTxs;
    bool fPrintPriority = params.printpriority;
    uint64_t nBlockSize = 1000;
    uint64_t nBlockTx = 0;
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    {
		EDCapp & theApp = EDCapp::singleton();
        LOCK2(EDC_cs_main, theApp.mempool().cs);
        CBlockIndex* pindexPrev = theApp.chainActive().Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = edcGetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        pblock->nVersion = edcComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
        // -regtest only: allow overriding block.nVersion with
        // -blockversion=N to test forking scenarios
        if (chainparams.MineBlocksOnDemand())
            pblock->nVersion = params.blockversion;

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & EDC_LOCKTIME_MEDIAN_TIME_PAST)
                                ? nMedianTimePast
                                : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock) 
		{
            vecPriority.reserve( theApp.mempool().mapTx.size());
            for (CEDCTxMemPool::indexed_transaction_set::iterator mi = theApp.mempool().mapTx.begin();
                 mi != theApp.mempool().mapTx.end(); ++mi)
            {
                double dPriority = mi->GetPriority(nHeight);
                CAmount dummy;
                theApp.mempool().ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
                vecPriority.push_back(EDCTxCoinAgePriority(dPriority, mi));
            }
            std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        }

        CEDCTxMemPool::indexed_transaction_set::index<mining_score>::type::iterator mi = theApp.mempool().mapTx.get<mining_score>().begin();
        CEDCTxMemPool::txiter iter;

        while (mi != theApp.mempool().mapTx.get<mining_score>().end() || !clearedTxs.empty())
        {
            bool priorityTx = false;
            if (fPriorityBlock && !vecPriority.empty()) 
			{ // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty()) 
			{ // add tx with next highest score
                iter = theApp.mempool().mapTx.project<0>(mi);
                mi++;
            }
            else 
			{  // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter))
                continue; // could have been added to the priorityBlock

            const CEDCTransaction& tx = iter->GetTx();

            bool fOrphan = false;
            BOOST_FOREACH(CEDCTxMemPool::txiter parent, theApp.mempool().GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent)) 
				{
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan) 
			{
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter,actualPriority));
                else
                    waitSet.insert(iter);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock &&
                (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) 
			{
                fPriorityBlock = false;
                waitPriMap.clear();
            }
            if (!priorityTx &&
                (iter->GetModifiedFee() < theApp.minRelayTxFee().GetFee(nTxSize) && nBlockSize >= nBlockMinSize)) 
			{
                break;
            }
            if (nBlockSize + nTxSize >= nBlockMaxSize) 
			{
                if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) 
				{
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000) 
				{
                    lastFewTxs++;
                }
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                continue;

            unsigned int nTxSigOps = iter->GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= EDC_MAX_BLOCK_SIGOPS) 
			{
                if (nBlockSigOps > EDC_MAX_BLOCK_SIGOPS - 2) 
				{
                    break;
                }
                continue;
            }

            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                double dPriority = iter->GetPriority(nHeight);
                CAmount dummy;
                theApp.mempool().ApplyDeltas(tx.GetHash(), dPriority, dummy);
                edcLogPrintf("priority %.1f fee %s txid %s\n",
                          dPriority , CFeeRate(iter->GetModifiedFee(), nTxSize).ToString(), tx.GetHash().ToString());
            }

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            BOOST_FOREACH(CEDCTxMemPool::txiter child, theApp.mempool().GetMemPoolChildren(iter))
            {
                if (fPriorityBlock) 
				{
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end()) 
					{
                        vecPriority.push_back(EDCTxCoinAgePriority(wpiter->second,child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else 
				{
                    if (waitSet.count(child)) 
					{
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }
        theApp.lastBlockTx( nBlockTx );
        theApp.lastBlockSize( nBlockSize );
        edcLogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

        // Compute final coinbase transaction.
        txNew.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0;
        pblock->vtx[0] = txNew;
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
        pblock->nNonce         = 0;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        CValidationState state;
        if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) 
		{
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
    }

    return pblocktemplate.release();
}

void IncrementExtraNonce(CEDCBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
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
	EDCapp & theApp = EDCapp::singleton();
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + theApp.coinbaseFlags();
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = edcBlockMerkleRoot(*pblock);
}
