// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_WALLET_EDCWALLETDB_H
#define EDC_WALLET_EDCWALLETDB_H

#include "wallet/walletdb.h"
#include "amount.h"
#include "edc/wallet/edcdb.h"
#include "key.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class CAccount;
class CAccountingEntry;
struct CBlockLocator;
class CKeyPool;
class CMasterKey;
class CScript;
class CEDCWallet;
class CEDCWalletTx;
class uint160;
class uint256;

/** Access to the wallet database */
class CEDCWalletDB : public CEDCDB
{
public:
    CEDCWalletDB(const std::string& strFilename, const char* pszMode = "r+", bool fFlushOnClose = true) : CEDCDB(strFilename, pszMode, fFlushOnClose)
    {
    }

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(const CEDCWalletTx& wtx);
    bool EraseTx(uint256 hash);

    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata &keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata &keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);

    bool WriteCScript(const uint160& hash, const CScript& redeemScript);

    bool WriteWatchOnly(const CScript &script);
    bool EraseWatchOnly(const CScript &script);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool WriteDefaultKey(const CPubKey& vchPubKey);

    bool ReadPool(int64_t nPool, CKeyPool& keypool);
    bool WritePool(int64_t nPool, const CKeyPool& keypool);
    bool ErasePool(int64_t nPool);

    bool WriteMinVersion(int nVersion);

    /// This writes directly to the database, and will not update the CEDCWallet's cached accounting entries!
    /// Use wallet.AddAccountingEntry instead, to write *and* update its caches.
    bool WriteAccountingEntry_Backend(const CAccountingEntry& acentry);
    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);

    /// Write destination data key,value tuple to database
    bool WriteDestData(const std::string &address, const std::string &key, const std::string &value);
    /// Erase destination data tuple from wallet database
    bool EraseDestData(const std::string &address, const std::string &key);

    CAmount GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    DBErrors ReorderTransactions(CEDCWallet* pwallet);
    DBErrors LoadWallet(CEDCWallet* pwallet);
    DBErrors FindWalletTx(CEDCWallet* pwallet, std::vector<uint256>& vTxHash, std::vector<CEDCWalletTx>& vWtx);
    DBErrors ZapWalletTx(CEDCWallet* pwallet, std::vector<CEDCWalletTx>& vWtx);
    DBErrors ZapSelectTx(CEDCWallet* pwallet, std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);
    static bool Recover(CEDCDBEnv& dbenv, const std::string& filename, bool fOnlyKeys);
    static bool Recover(CEDCDBEnv& dbenv, const std::string& filename);

private:
    CEDCWalletDB(const CEDCWalletDB&);
    void operator=(const CEDCWalletDB&);

    bool WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry);
};

bool BackupWallet(const CEDCWallet& wallet, const std::string& strDest);
void edcThreadFlushWalletDB(const std::string& strFile);

#endif // BITCOIN_WALLET_WALLETDB_H