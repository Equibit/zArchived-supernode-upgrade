// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcmerkleblock.h"

#include "hash.h"
#include "consensus/consensus.h"
#include "utilstrencodings.h"

using namespace std;

CEDCMerkleBlock::CEDCMerkleBlock(const CEDCBlock& block, CEDCBloomFilter& filter)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const uint256& hash = block.vtx[i].GetHash();
        if (filter.IsRelevantAndUpdate(block.vtx[i]))
        {
            vMatch.push_back(true);
            vMatchedTxn.push_back(make_pair(i, hash));
        }
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}

CEDCMerkleBlock::CEDCMerkleBlock(const CEDCBlock& block, const std::set<uint256>& txids)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const uint256& hash = block.vtx[i].GetHash();
        if (txids.count(hash))
            vMatch.push_back(true);
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}
