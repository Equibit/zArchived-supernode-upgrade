// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDCMERKLEBLOCK_H
#define EDC_EDCMERKLEBLOCK_H

#include "merkleblock.h"
#include "serialize.h"
#include "uint256.h"
#include "edc/primitives/edcblock.h"
#include "edcbloom.h"

#include <vector>

/**
 * Used to relay blocks as header + vector<merkle branch>
 * to filtered nodes.
 */
class CEDCMerkleBlock
{
public:
    /** Public only for unit testing */
    CBlockHeader header;
    CPartialMerkleTree txn;

public:
    /** Public only for unit testing and relay testing (not relayed) */
    std::vector<std::pair<unsigned int, uint256> > vMatchedTxn;

    /**
     * Create from a CBlock, filtering transactions according to filter
     * Note that this will call IsRelevantAndUpdate on the filter for each transaction,
     * thus the filter will likely be modified.
     */
    CEDCMerkleBlock(const CEDCBlock& block, CEDCBloomFilter& filter);

    // Create from a CBlock, matching the txids in the set
    CEDCMerkleBlock(const CEDCBlock& block, const std::set<uint256>& txids);

    CEDCMerkleBlock() {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(header);
        READWRITE(txn);
    }
};

#endif // BITCOIN_MERKLEBLOCK_H
