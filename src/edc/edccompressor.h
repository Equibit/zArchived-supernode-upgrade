// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDCCOMPRESSOR_H
#define EDC_EDCCOMPRESSOR_H

#include "compressor.h"
#include "edc/primitives/edctransaction.h"
#include "script/script.h"
#include "serialize.h"


class CKeyID;
class CPubKey;
class CScriptID;

/** wrapper for CEDCTxOut that provides a more compact serialization */
class CEDCTxOutCompressor
{
private:
    CEDCTxOut &txout;

public:
    static uint64_t CompressAmount(uint64_t nAmount);
    static uint64_t DecompressAmount(uint64_t nAmount);

    CEDCTxOutCompressor(CEDCTxOut &txoutIn) : txout(txoutIn) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        if (!ser_action.ForRead()) 
		{
            uint64_t nVal = CompressAmount(txout.nValue);
            READWRITE(VARINT(nVal));
        } 
		else 
		{
            uint64_t nVal = 0;
            READWRITE(VARINT(nVal));
            txout.nValue = DecompressAmount(nVal);
        }
        CScriptCompressor cscript(REF(txout.scriptPubKey));
        READWRITE(cscript);
    }
};

#endif // BITCOIN_COMPRESSOR_H