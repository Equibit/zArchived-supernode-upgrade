// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDCTXDB_H
#define EDC_EDCTXDB_H

#include "txdb.h"
#include "edccoins.h"
#include "dbwrapper.h"
#include "chain.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <boost/function.hpp>

class CBlockIndex;
class CEDCCoinsViewDBCursor;
class uint256;

#if 0
//! -dbcache default (MiB)
static const int64_t nDefaultDbCache = 100;
//! max. -dbcache in (MiB)
static const int64_t nMaxDbCache = sizeof(void*) > 4 ? 16384 : 1024;
//! min. -dbcache in (MiB)
static const int64_t nMinDbCache = 4;

struct CDiskTxPos : public CDiskBlockPos
{
    unsigned int nTxOffset; // after header

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CDiskBlockPos*)this);
        READWRITE(VARINT(nTxOffset));
    }

    CDiskTxPos(const CDiskBlockPos &blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn) {
    }

    CDiskTxPos() {
        SetNull();
    }

    void SetNull() {
        CDiskBlockPos::SetNull();
        nTxOffset = 0;
    }
};
#endif

/** CCoinsView backed by the coin database (chainstate/) */
class CEDCCoinsViewDB : public CEDCCoinsView
{
protected:
    CDBWrapper db;
public:
    CEDCCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetCoins(const uint256 &txid, CEDCCoins &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    bool BatchWrite(CEDCCoinsMap &mapCoins, const uint256 &hashBlock);
    CEDCCoinsViewCursor *Cursor() const;
};

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CEDCCoinsViewDBCursor: public CEDCCoinsViewCursor
{
public:
    ~CEDCCoinsViewDBCursor() {}

    bool GetKey(uint256 &key) const;
    bool GetValue(CEDCCoins &coins) const;
    unsigned int GetValueSize() const;

    bool Valid() const;
    void Next();

private:
    CEDCCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256 &hashBlockIn):
        CEDCCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
    boost::scoped_ptr<CDBIterator> pcursor;
    std::pair<char, uint256> keyTmp;

    friend class CEDCCoinsViewDB;
};

/** Access to the block database (blocks/index/) */
class CEDCBlockTreeDB : public CDBWrapper
{
public:
    CEDCBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
private:
    CEDCBlockTreeDB(const CEDCBlockTreeDB&);
    void operator=(const CEDCBlockTreeDB&);
public:
    bool WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo &fileinfo);
    bool ReadLastBlockFile(int &nFile);
    bool WriteReindexing(bool fReindex);
    bool ReadReindexing(bool &fReindex);
    bool ReadTxIndex(const uint256 &txid, CDiskTxPos &pos);
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> > &list);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
    bool LoadBlockIndexGuts(boost::function<CBlockIndex*(const uint256&)> insertBlockIndex);
};

#endif
