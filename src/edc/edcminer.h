// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "edc/primitives/edcblock.h"
#include "edctxmempool.h"

#include <stdint.h>
#include <memory>

class CBlockIndex;
class CEDCChainParams;
class CEDCReserveKey;
class CScript;
class CEDCWallet;

namespace Consensus { struct Params; };

static const bool EDC_DEFAULT_PRINTPRIORITY = false;

struct CEDCBlockTemplate
{
    CEDCBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

/** Generate a new block, without valid proof-of-work */
class EDCBlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CEDCBlockTemplate> pblocktemplate;

    // A convenience pointer that always refers to the CBlock in pblocktemplate
    CEDCBlock* pblock;

    // Configuration parameters for the block size
    unsigned int nBlockMaxSize, nBlockMinSize;

    // Information on the current status of the block
    uint64_t nBlockSize;
    uint64_t nBlockTx;
    unsigned int nBlockSigOps;
    CAmount nFees;
    CEDCTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;
    const CEDCChainParams& chainparams;

    // Variables used for addScoreTxs and addPriorityTxs
    int lastFewTxs;
    bool blockFinished;

public:
    EDCBlockAssembler(const CEDCChainParams& chainparams);

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    CEDCBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn);

private:
    // utility functions

    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();

    /** Add a tx to the block */
    void AddToBlock(CEDCTxMemPool::txiter iter);

    // Methods for how to add transactions to a block.

    /** Add transactions based on modified feerate */
    void addScoreTxs();

    /** Add transactions based on tx "priority" */
    void addPriorityTxs();

    // helper function for addScoreTxs and addPriorityTxs

    /** Test if tx will still "fit" in the block */
    bool TestForBlock(CEDCTxMemPool::txiter iter);

    /** Test if tx still has unconfirmed parents not yet in block */
    bool isStillDependent(CEDCTxMemPool::txiter iter);
};

/** Modify the extranonce in a block */
void IncrementExtraNonce(CEDCBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
int64_t UpdateTime( CBlockHeader * pblock, const Consensus::Params & consensusParams, const CBlockIndex* pindexPrev);
