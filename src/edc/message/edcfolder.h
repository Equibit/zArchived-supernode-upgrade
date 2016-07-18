// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "primitives/block.h"
#include "edc/message/edcmessage.h"
#include "serialize.h"
#include "uint256.h"

// This class is used to store User Messages. It is the User Message
// equivalent of CEDCBlock
//
class CFolder : public CBlockHeader
{
public:
    std::vector<CUserMessage *> vtx;

    // memory only
    mutable bool fChecked;

    CFolder()
    {
        SetNull();
    }

    CFolder(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(*(CBlockHeader*)this);
		READWRITE(vtx.size());
       	for( size_t i = 0; i < vtx.size(); ++i )
			READWRITE(*vtx[i]);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();

		std::vector<CUserMessage *>::iterator i = vtx.begin();
		std::vector<CUserMessage *>::iterator e = vtx.end();
		while( i != e )
		{
			delete *i;
			++i;
		}
		
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

