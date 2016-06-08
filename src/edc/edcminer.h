// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDCMINER_H
#define EDC_EDCMINER_H

#include "miner.h"
#include "edc/primitives/edcblock.h"

#include <stdint.h>

class CBlockIndex;
class CEDCChainParams;
class CEDCReserveKey;
class CScript;
class CEDCWallet;
namespace Consensus { struct Params; };

struct CEDCBlockTemplate
{
    CEDCBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

/** Generate a new block, without valid proof-of-work */
CEDCBlockTemplate* CreateNewEDCBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CEDCBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);

#endif // BITCOIN_MINER_H
