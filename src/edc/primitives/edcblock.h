// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_PRIMITIVES_EDCBLOCK_H
#define EDC_PRIMITIVES_EDCBLOCK_H

#include "primitives/block.h"
#include "edc/primitives/edctransaction.h"
#include "serialize.h"
#include "uint256.h"


class CEDCBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CEDCTransaction> vtx;

    // memory only
    mutable bool fChecked;

    CEDCBlock()
    {
        SetNull();
    }

    CEDCBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    std::string ToString() const;
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H