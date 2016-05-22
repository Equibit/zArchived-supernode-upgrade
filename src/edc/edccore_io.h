// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDCCORE_IO_H
#define EDC_EDCCORE_IO_H

#include <string>
#include <vector>
#include "core_io.h"

class CEDCBlock;
class CScript;
class CEDCTransaction;
class uint256;
class UniValue;

// core_read.cpp
extern CScript edcParseScript(const std::string& s);
extern bool DecodeHexTx(CEDCTransaction& tx, const std::string& strHexTx);
extern bool DecodeHexBlk(CEDCBlock&, const std::string& strHexBlk);
extern uint256 edcParseHashStr(const std::string&, const std::string& strName);
extern std::vector<unsigned char> ParseHexUV(const UniValue& v, const std::string& strName);

// core_write.cpp
extern std::string edcFormatScript(const CScript& script);
extern std::string EncodeHexTx(const CEDCTransaction& tx);
extern void edcScriptPubKeyToUniv(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);
extern void TxToUniv(const CEDCTransaction& tx, const uint256& hashBlock, UniValue& entry);

#endif // BITCOIN_CORE_IO_H
