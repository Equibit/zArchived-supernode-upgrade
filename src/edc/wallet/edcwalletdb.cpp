// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/wallet/edcwalletdb.h"

#include "edc/edcbase58.h"
#include "consensus/validation.h"
#include "edc/edcmain.h" // For CheckTransaction
#include "protocol.h"
#include "serialize.h"
#include "sync.h"
#include "edc/edcutil.h"
#include "utiltime.h"
#include "edc/wallet/edcwallet.h"
#include "edc/edcparams.h"
#include "edc/edcapp.h"

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>

using namespace std;

static uint64_t nAccountingEntryNumber = 0;


bool CEDCWalletDB::WriteName(const string& strAddress, const string& strName)
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.incWalletDBUpdated();

    return Write(make_pair(string("name"), strAddress), strName);
}

bool CEDCWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(make_pair(string("name"), strAddress));
}

bool CEDCWalletDB::WritePurpose(const string& strAddress, const string& strPurpose)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(make_pair(string("purpose"), strAddress), strPurpose);
}

bool CEDCWalletDB::ErasePurpose(const string& strPurpose)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(make_pair(string("purpose"), strPurpose));
}

bool CEDCWalletDB::WriteTx(const CEDCWalletTx& wtx)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(std::string("tx"), wtx.GetHash()), wtx);
}

bool CEDCWalletDB::EraseTx(uint256 hash)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(std::make_pair(std::string("tx"), hash));
}

bool CEDCWalletDB::WriteKey(
	 	 const CPubKey & vchPubKey, 
		const CPrivKey & vchPrivKey, 
	const CKeyMetadata & keyMeta)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey),
               keyMeta, false))
        return false;

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return Write(std::make_pair(std::string("key"), vchPubKey), 
		std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool CEDCWalletDB::WriteCryptedKey(
	                   const CPubKey & vchPubKey,
    const std::vector<unsigned char> & vchCryptedSecret,
                  const CKeyMetadata & keyMeta)
{
	EDCapp & theApp = EDCapp::singleton();

    const bool fEraseUnencryptedKey = true;
    theApp.incWalletDBUpdated();

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey), keyMeta))
        return false;

    if (!Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
        return false;

    if (fEraseUnencryptedKey)
    {
        Erase(std::make_pair(std::string("key"), vchPubKey));
        Erase(std::make_pair(std::string("wkey"), vchPubKey));
    }

    return true;
}

bool CEDCWalletDB::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool CEDCWalletDB::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(std::string("cscript"), hash), *(const CScriptBase*)(&redeemScript), false);
}

bool CEDCWalletDB::WriteWatchOnly(const CScript &dest)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(std::string("watchs"), *(const CScriptBase*)(&dest)), '1');
}

bool CEDCWalletDB::EraseWatchOnly(const CScript &dest)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(std::make_pair(std::string("watchs"), *(const CScriptBase*)(&dest)));
}

bool CEDCWalletDB::WriteBestBlock(const CBlockLocator& locator)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    Write(std::string("bestblock"), CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan

    return Write(std::string("bestblock_nomerkle"), locator);
}

bool CEDCWalletDB::ReadBestBlock(CBlockLocator& locator)
{
    if (Read(std::string("bestblock"), locator) && !locator.vHave.empty()) 
		return true;

    return Read(std::string("bestblock_nomerkle"), locator);
}

bool CEDCWalletDB::WriteOrderPosNext(int64_t nOrderPosNext)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::string("orderposnext"), nOrderPosNext);
}

bool CEDCWalletDB::WriteDefaultKey(const CPubKey& vchPubKey)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::string("defaultkey"), vchPubKey);
}

bool CEDCWalletDB::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CEDCWalletDB::WritePool(int64_t nPool, const CKeyPool& keypool)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CEDCWalletDB::ErasePool(int64_t nPool)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(std::make_pair(std::string("pool"), nPool));
}

bool CEDCWalletDB::WriteMinVersion(int nVersion)
{
    return Write(std::string("minversion"), nVersion);
}

bool CEDCWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull();
    return Read(make_pair(string("acc"), strAccount), account);
}

bool CEDCWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return Write(make_pair(string("acc"), strAccount), account);
}

bool CEDCWalletDB::ReadIssuer(const string& strIssuer, CIssuer & issuer )
{
    issuer.SetNull();
    return Read(make_pair(string("issuer"), strIssuer), issuer );
}

bool CEDCWalletDB::WriteIssuer(const string& strIssuer, const CIssuer & issuer )
{
    return Write(make_pair(string("issuer"), strIssuer), issuer );
}

bool CEDCWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry)
{
    return Write(std::make_pair(std::string("acentry"), 
		std::make_pair(acentry.strAccount, nAccEntryNum)), acentry);
}

bool CEDCWalletDB::WriteAccountingEntry_Backend(const CAccountingEntry& acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

CAmount CEDCWalletDB::GetAccountCreditDebit(const string& strAccount)
{
    list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    CAmount nCreditDebit = 0;
    BOOST_FOREACH (const CAccountingEntry& entry, entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CEDCWalletDB::ListAccountCreditDebit(const string& strAccount, list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error("CEDCWalletDB::ListAccountCreditDebit(): cannot create DB cursor");

    unsigned int fFlags = DB_SET_RANGE;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::make_pair(std::string("acentry"), 
				std::make_pair((fAllAccounts ? string("") : strAccount), uint64_t(0)));

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;

        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("CEDCWalletDB::ListAccountCreditDebit(): error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;

        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
}

DBErrors CEDCWalletDB::ReorderTransactions(CEDCWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CEDCWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef pair<CEDCWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (map<uint256, CEDCWalletTx>::iterator it = pwallet->mapWallet.begin(); 
	it != pwallet->mapWallet.end(); ++it)
    {
        CEDCWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }

    list<CAccountingEntry> acentries;
    ListAccountCreditDebit("", acentries);

    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CEDCWalletTx*)0, &entry)));
    }

    int64_t& nOrderPosNext = pwallet->nOrderPosNext;
    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CEDCWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pwtx)
            {
                if (!WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            BOOST_FOREACH(const int64_t& nOffsetStart, nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx)
            {
                if (!WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }
    WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

class CWalletScanState 
{
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    vector<uint256> vWalletUpgrade;

    CWalletScanState() {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool
ReadKeyValue(
	      CEDCWallet * pwallet, 
       	 CDataStream & ssKey, 
      	 CDataStream & ssValue,
    CWalletScanState & wss, 
	          string & strType, 
	          string & strErr)
{
    try 
	{
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;

        if (strType == "name")
        {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CEDCBitcoinAddress(strAddress).Get()].name;
        }
        else if (strType == "purpose")
        {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CEDCBitcoinAddress(strAddress).Get()].purpose;
        }
        else if (strType == "tx")
        {
            uint256 hash;
            ssKey >> hash;
            CEDCWalletTx wtx;
            ssValue >> wtx;
            CValidationState state;
            if (!(CheckTransaction(wtx, state) && (wtx.GetHash() == hash) && state.IsValid()))
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!ssValue.empty())
                {
                    char fTmp;
                    char fUnused;
                    ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d '%s' %s",
                        wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", 
                        wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            pwallet->AddToWallet(wtx, true, NULL);
        }
        else if (strType == "acentry")
        {
            string strAccount;
            ssKey >> strAccount;
            uint64_t nNumber;
            ssKey >> nNumber;
            if (nNumber > nAccountingEntryNumber)
                nAccountingEntryNumber = nNumber;

            if (!wss.fAnyUnordered)
            {
                CAccountingEntry acentry;
                ssValue >> acentry;
                if (acentry.nOrderPos == -1)
                    wss.fAnyUnordered = true;
            }
        }
        else if (strType == "watchs")
        {
            CScript script;
            ssKey >> *(CScriptBase*)(&script);
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadWatchOnly(script);

            // Watch-only addresses have no birthday information for now,
            // so set the wallet birthday to the beginning of time.
            pwallet->nTimeFirstKey = 1;
        }
        else if (strType == "key" || strType == "wkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            if (strType == "key")
            {
                wss.nKeys++;
                ssValue >> pkey;
            } 
			else 
			{
                CWalletKey wkey;
                ssValue >> wkey;
                pkey = wkey.vchPrivKey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the 
            // public key is re-derived from the private key using EC 
            // operations as a checksum. Newer wallets store keys as 
            // "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much 
			// faster while remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch (...) 
			{
            	edcLogPrintf("Warning: Exception thrown during key input processing\n");
			}

            bool fSkipCheck = false;

            if (!hash.IsNull())
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        }
        else if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == "ckey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "keymeta")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(vchPubKey, keyMeta);

            // find earliest key creation time, as wallet birthday
            if (!pwallet->nTimeFirstKey ||
                (keyMeta.nCreateTime < pwallet->nTimeFirstKey))
                pwallet->nTimeFirstKey = keyMeta.nCreateTime;
        }
        else if (strType == "defaultkey")
        {
            ssValue >> pwallet->vchDefaultKey;
        }
        else if (strType == "pool")
        {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;
            pwallet->setKeyPool.insert(nIndex);

            // If no metadata exists yet, create a default with the pool key's
            // creation time. Note that this may be overwritten by actually
            // stored metadata for that key later, which is fine.
            CKeyID keyid = keypool.vchPubKey.GetID();
            if (pwallet->mapKeyMetadata.count(keyid) == 0)
                pwallet->mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
        }
        else if (strType == "version")
        {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        }
        else if (strType == "cscript")
        {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> *(CScriptBase*)(&script);
            if (!pwallet->LoadCScript(script))
            {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        }
        else if (strType == "orderposnext")
        {
            ssValue >> pwallet->nOrderPosNext;
        }
        else if (strType == "destdata")
        {
            std::string strAddress, strKey, strValue;
            ssKey >> strAddress;
            ssKey >> strKey;
            ssValue >> strValue;
            if (!pwallet->LoadDestData(CEDCBitcoinAddress(strAddress).Get(), strKey, strValue))
            {
                strErr = "Error reading wallet database: LoadDestData failed";
                return false;
            }
        }
    } catch (...)
    {
        return false;
    }
    return true;
}

static bool IsKeyType(string strType)
{
    return (strType== "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey");
}

DBErrors CEDCWalletDB::LoadWallet(CEDCWallet* pwallet)
{
    pwallet->vchDefaultKey = CPubKey();
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try 
	{
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            edcLogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                edcLogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
                else
                {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == "tx")
					{
						EDCparams & params = EDCparams::singleton();
                        // Rescan if there is a bad transaction record:
						if( mapArgs.count( "-eb_rescan" ) == 0 )
	                        params.rescan = true;
					}
                }
            }
            if (!strErr.empty())
                edcLogPrintf("%s\n", strErr);
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) 
	{
        throw;
    }
    catch (...) 
	{
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DB_LOAD_OK)
        return result;

    edcLogPrintf("nFileVersion = %d\n", wss.nFileVersion);

    edcLogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
           wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta)
        pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'

    BOOST_FOREACH(uint256 hash, wss.vWalletUpgrade)
        WriteTx(pwallet->mapWallet[hash]);

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
        return DB_NEED_REWRITE;

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
        result = ReorderTransactions(pwallet);

    pwallet->laccentries.clear();
    ListAccountCreditDebit("*", pwallet->laccentries);
    BOOST_FOREACH(CAccountingEntry& entry, pwallet->laccentries) 
	{
        pwallet->wtxOrdered.insert(make_pair(entry.nOrderPos, CEDCWallet::TxPair((CEDCWalletTx*)0, &entry)));
    }

    return result;
}

DBErrors CEDCWalletDB::FindWalletTx(
			  CEDCWallet * pwallet, 
		 vector<uint256> & vTxHash, 
	vector<CEDCWalletTx> & vWtx)
{
    pwallet->vchDefaultKey = CPubKey();
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try 
	{
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            edcLogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                edcLogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            string strType;
            ssKey >> strType;
            if (strType == "tx") 
			{
                uint256 hash;
                ssKey >> hash;

                CEDCWalletTx wtx;
                ssValue >> wtx;

                vTxHash.push_back(hash);
                vWtx.push_back(wtx);
            }
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) 
	{
        throw;
    }
    catch (...) 
	{
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    return result;
}

DBErrors CEDCWalletDB::ZapSelectTx(
		 CEDCWallet * pwallet, 
	vector<uint256> & vTxHashIn, 
	vector<uint256> & vTxHashOut)
{
    // build list of wallet TXs and hashes
    vector<uint256> vTxHash;
    vector<CEDCWalletTx> vWtx;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx);

    if (err != DB_LOAD_OK) 
	{
        return err;
    }

    std::sort(vTxHash.begin(), vTxHash.end());
    std::sort(vTxHashIn.begin(), vTxHashIn.end());

    // erase each matching wallet TX
    bool delerror = false;
    vector<uint256>::iterator it = vTxHashIn.begin();
    BOOST_FOREACH (uint256 hash, vTxHash) 
	{
        while (it < vTxHashIn.end() && (*it) < hash) 
		{
            it++;
        }
        if (it == vTxHashIn.end()) 
		{
            break;
        }
        else if ((*it) == hash) 
		{
            pwallet->mapWallet.erase(hash);
            if(!EraseTx(hash)) 
			{
                edcLogPrint("db", "Transaction was found for deletion but returned database error: %s\n", hash.GetHex());
                delerror = true;
            }
            vTxHashOut.push_back(hash);
        }
    }

    if (delerror) 
	{
        return DB_CORRUPT;
    }
    return DB_LOAD_OK;
}

DBErrors CEDCWalletDB::ZapWalletTx(CEDCWallet* pwallet, vector<CEDCWalletTx>& vWtx)
{
    // build list of wallet TXs
    vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx);
    if (err != DB_LOAD_OK)
        return err;

    // erase each wallet TX
    BOOST_FOREACH (uint256& hash, vTxHash) 
	{
        if (!EraseTx(hash))
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

void edcThreadFlushWalletDB(const string& strFile)
{
	EDCapp & theApp = EDCapp::singleton();

    // Make this thread recognisable as the wallet flushing thread
    RenameThread("bitcoin-wallet");

    static bool fOneThread;
    if (fOneThread)
        return;
    fOneThread = true;
	EDCparams & params = EDCparams::singleton();
    if (!params.flushwallet )
        return;

    unsigned int nLastSeen = theApp.walletDBUpdated();
    unsigned int nLastFlushed = theApp.walletDBUpdated();
    int64_t nLastWalletUpdate = GetTime();
    while (true)
    {
        MilliSleep(500);

        if (nLastSeen != theApp.walletDBUpdated() )
        {
            nLastSeen = theApp.walletDBUpdated();
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != theApp.walletDBUpdated() && GetTime() - nLastWalletUpdate >= 2)
        {
            TRY_LOCK(theApp.bitdb().cs_db,lockDb);
            if (lockDb)
            {
                // Don't do this if any databases are in use
                int nRefCount = 0;
                map<string, int>::iterator mi = theApp.bitdb().mapFileUseCount.begin();
                while (mi != theApp.bitdb().mapFileUseCount.end())
                {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0)
                {
                    boost::this_thread::interruption_point();
                    map<string, int>::iterator mi = theApp.bitdb().mapFileUseCount.find(strFile);
                    if (mi != theApp.bitdb().mapFileUseCount.end())
                    {
                        edcLogPrint("db", "Flushing %s\n", strFile);
                        nLastFlushed = theApp.walletDBUpdated();
                        int64_t nStart = GetTimeMillis();

                        // Flush wallet file so it's self contained
                        theApp.bitdb().CloseDb(strFile);
                        theApp.bitdb().CheckpointLSN(strFile);

                        theApp.bitdb().mapFileUseCount.erase(mi++);
                        edcLogPrint("db", "Flushed %s %dms\n", strFile, GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

bool BackupWallet(const CEDCWallet& wallet, const string& strDest)
{
	EDCapp & theApp = EDCapp::singleton();

    if (!wallet.fFileBacked)
        return false;
    while (true)
    {
        {
            LOCK(theApp.bitdb().cs_db);
            if (!theApp.bitdb().mapFileUseCount.count(wallet.strWalletFile) || 
				 theApp.bitdb().mapFileUseCount[wallet.strWalletFile] == 0)
            {
                // Flush log data to the dat file
                theApp.bitdb().CloseDb(wallet.strWalletFile);
                theApp.bitdb().CheckpointLSN(wallet.strWalletFile);
                theApp.bitdb().mapFileUseCount.erase(wallet.strWalletFile);

                // Copy wallet file
                boost::filesystem::path pathSrc = edcGetDataDir() / wallet.strWalletFile;
                boost::filesystem::path pathDest(strDest);
                if (boost::filesystem::is_directory(pathDest))
                    pathDest /= wallet.strWalletFile;

                try 
				{
#if BOOST_VERSION >= 104000
                    boost::filesystem::copy_file(pathSrc, pathDest, boost::filesystem::copy_option::overwrite_if_exists);
#else
                    boost::filesystem::copy_file(pathSrc, pathDest);
#endif
                    edcLogPrintf("copied %s to %s\n", wallet.strWalletFile, pathDest.string());
                    return true;
                } 
				catch (const boost::filesystem::filesystem_error& e) 
				{
                    edcLogPrintf("error copying %s to %s - %s\n", wallet.strWalletFile, pathDest.string(), e.what());
                    return false;
                }
            }
        }
        MilliSleep(100);
    }
    return false;
}

//
// Try to (very carefully!) recover wallet file if there is a problem.
//
bool CEDCWalletDB::Recover(
	           CEDCDBEnv & dbenv, 
       const std::string & filename, 
	                  bool fOnlyKeys )
{
    // Recovery procedure:
    // move wallet file to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to fresh wallet file
    // Set -eb_rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("wallet.%d.bak", now);

    int result = dbenv.dbenv->dbrename(NULL, filename.c_str(), NULL,
                                       newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        edcLogPrintf("Renamed %s to %s\n", filename, newFilename);
    else
    {
        edcLogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::vector<CEDCDBEnv::KeyValPair> salvagedData;
    bool fSuccess = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty())
    {
        edcLogPrintf("Salvage(aggressive) found no records in %s.\n", 
			newFilename);
        return false;
    }
    edcLogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size());

    boost::scoped_ptr<Db> pdbCopy(new Db(dbenv.dbenv, 0));
    int ret = pdbCopy->open(NULL,               // Txn pointer
                            filename.c_str(),   // Filename
                            "main",             // Logical db name
                            DB_BTREE,           // Database type
                            DB_CREATE,          // Flags
                            0);
    if (ret > 0)
    {
        edcLogPrintf("Cannot create database file %s\n", filename);
        return false;
    }
    CEDCWallet dummyWallet;
    CWalletScanState wss;

    DbTxn* ptxn = dbenv.TxnBegin();
    BOOST_FOREACH(CEDCDBEnv::KeyValPair& row, salvagedData)
    {
        if (fOnlyKeys)
        {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
            string strType, strErr;
            bool fReadOK;
            {
                // Required in LoadKeyMetadata():
                LOCK(dummyWallet.cs_wallet);
                fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue,
                                        wss, strType, strErr);
            }
            if (!IsKeyType(strType))
                continue;
            if (!fReadOK)
            {
                edcLogPrintf("WARNING: CEDCWalletDB::Recover skipping %s: %s\n",
					strType, strErr);
                continue;
            }
        }

        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);

        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}

bool CEDCWalletDB::Recover(CEDCDBEnv& dbenv, const std::string& filename)
{
    return CEDCWalletDB::Recover(dbenv, filename, false);
}

bool CEDCWalletDB::WriteDestData(
	const std::string & address, 
	const std::string & key, 
	const std::string & value)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Write(std::make_pair(std::string("destdata"), 
		std::make_pair(address, key)), value);
}

bool CEDCWalletDB::EraseDestData(const std::string &address, const std::string &key)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.incWalletDBUpdated();
    return Erase(std::make_pair(std::string("destdata"), std::make_pair(address, key)));
}

namespace
{

bool dumpKey( 
	    ostream & out,
	CDataStream & ssKey,
         string & strType )
{
    try 
	{
        ssKey >> strType;
		out << strType;

        if (strType == "name")
        {
            string strAddress;
            ssKey >> strAddress;
			out << ':' << strAddress;
        }
        else if (strType == "purpose")
        {
            string strAddress;
            ssKey >> strAddress;
			out << ':' << strAddress;
        }
        else if (strType == "tx")
        {
            uint256 hash;
            ssKey >> hash;
			out << ':' << hash.ToString();
        }
        else if (strType == "acentry")
        {
            string strAccount;
            uint64_t nNumber;

            ssKey >> strAccount;
            ssKey >> nNumber;

			out << ':' << strAccount << ':' << nNumber;
        }
        else if (strType == "watchs")
        {
            CScript script;
            ssKey >> *static_cast<CScriptBase *>(&script);
			out << HexStr(script);
        }
        else if (strType == "key" || strType == "wkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
			out << ':' << HexStr( vchPubKey );
        }
        else if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
			out << ':' << nID;
        }
        else if (strType == "ckey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
			out << ':' << HexStr( vchPubKey );
        }
        else if (strType == "keymeta")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
			out << ':' << HexStr( vchPubKey );
        }
        else if (strType == "defaultkey")
        {
			// no-op
        }
        else if (strType == "pool")
        {
            int64_t nIndex;
            ssKey >> nIndex;
			out << ':' << nIndex;
        }
        else if (strType == "version")
        {
			// no-op
        }
        else if (strType == "cscript")
        {
            uint160 hash;
            ssKey >> hash;
			out << ':' << hash.ToString();
        }
        else if (strType == "orderposnext")
        {
			// no-op
        }
        else if (strType == "destdata")
        {
            std::string strAddress;
            ssKey >> strAddress;

            std::string strKey;
            ssKey >> strKey;

			out << ':' << strAddress << ':' << strKey;
        }
		else if( strType == "bestblock" )
		{
			// no-op
		}
		else if( strType == "bestblock_nomerkle" )
		{
			// no-op
		}
		else if( strType == "minversion" )
		{
			// no-op
		}
		else if( strType == "acc" )
		{
            std::string name;
            ssKey >> name;
			out << ':' << name;
		}
		else if( strType == "issuer" )
		{
            std::string name;
            ssKey >> name;
			out << ':' << name;
		}
		else
		{
			out << "ERROR: Unsupported key [" << strType  << "]" << endl;
		}

		out << endl;
    } 
	catch (...)
    {
        return false;
    }

    return true;
}

bool
dumpValue(
			 ostream & out,
			  string & strType,
      	 CDataStream & ssValue )
{
    try 
	{
        if (strType == "name")
        {
			string name;
            ssValue >> name;
			out << " \"" << name << "\"" << endl;
        }
        else if (strType == "purpose")
        {
			string purpose;
            ssValue >> purpose;
			out << " \"" << purpose << "\"" << endl;
        }
        else if (strType == "tx")
        {
            CEDCWalletTx wtx;
            ssValue >> wtx;
			out << wtx.toJSON( " " );
        }
        else if (strType == "acentry")
        {
            CAccountingEntry acentry;
            ssValue >> acentry;

			out << " {\"account\":" << acentry.strAccount 
				<< " \",creditDebit\":" << acentry.nCreditDebit
				<< " \",time\":" << acentry.nTime
				<< " \",otherAccount\":" << acentry.strOtherAccount
				<< " \",comment\":" << acentry.strComment
				<< " \",mapValue\":[";

			auto i = acentry.mapValue.begin();
			auto e = acentry.mapValue.end();
			bool first = true;
			while( i != e )
			{
				if(!first)
					out << ",";
				else
					first = false;

				out << "[" << i->first << "," << i->second << "]";
				++i;
			}
			out << "]";

			out	<< " \",orderPos\":" << acentry.nOrderPos
				<< " \",entryNo\":" << acentry.nEntryNo
				<< "}\n";
        }
        else if (strType == "watchs")
        {
            char fYes;
            ssValue >> fYes;
			out << " " << fYes << endl;
        }
        else if (strType == "key" )
        {
            CPrivKey pkey;
            uint256 hash;

            ssValue >> pkey;
            ssValue >> hash;

			out << " {\"key\":" << HexStr(pkey) << ",\"hash\":" << hash.ToString() << "}\n";
        }
        else if (strType == "mkey")
        {
            CMasterKey masterKey;
            ssValue >> masterKey;

			out << " {";
			out << "  \"cryptedKey\":" << HexStr(masterKey.vchCryptedKey) << "," << endl;
			out << "  \"salt\":" << HexStr(masterKey.vchSalt) << "," << endl;
			out << "  \"derivationMethod\":" << masterKey.nDerivationMethod << "," << endl;
			out << "  \"derivationIterations\":" << masterKey.nDeriveIterations << "," << endl;
			out << "  \"otherDerivationParamters\":" << HexStr(masterKey.vchOtherDerivationParameters) << endl;

			out << " }\n";
        }
        else if (strType == "ckey")
        {
            vector<unsigned char> privKey;
            ssValue >> privKey;

			out << " " << HexStr( privKey ) << endl;
        }
        else if (strType == "keymeta")
        {
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;

			std::string t = ctime( &keyMeta.nCreateTime );
			t = t.substr( 0, t.size() - 1 );

			out << "{\"version\":" << keyMeta.nVersion << ", \"createTime\":" << t << "}" << endl;
        }
        else if (strType == "defaultkey")
        {
			CPubKey defaultKey;
            ssValue >> defaultKey;
			out << " " << HexStr( defaultKey ) << endl;
        }
        else if (strType == "pool")
        {
            CKeyPool keypool;
            ssValue >> keypool;

			out << " {\"pool\":" << keypool.nTime << ", \"pubKey\":" << 
				HexStr(keypool.vchPubKey) << "}" << endl;
        }
        else if (strType == "version")
        {
			int fileVersion;
            ssValue >> fileVersion;
			out << " " << fileVersion << endl;
        }
        else if (strType == "cscript")
        {
            CScript script;
            ssValue >> *(CScriptBase*)(&script);
			out << " " << HexStr(script) << endl;
        }
        else if (strType == "orderposnext")
        {
			int64_t orderPosNext;
			ssValue >> orderPosNext;
			out << " " << orderPosNext << endl;
        }
        else if (strType == "destdata")
        {
            std::string strValue;
            ssValue >> strValue;
			out << " " << strValue << endl;
        }
		else if( strType == "bestblock" )
		{
			CBlockLocator locator;
			ssValue >> locator;

			out << " [\n";

			auto i = locator.vHave.begin();
			auto e = locator.vHave.end();

			bool first = true;
			while( i != e )
			{
				if(!first)
					out << ",\n";
				else
					first = false;
	
				out << HexStr(*i);
				++i;
			}

			out << "\n ]\n";
		}
		else if( strType == "bestblock_nomerkle" )
		{
			CBlockLocator locator;
			ssValue >> locator;

			out << " [\n";

			auto i = locator.vHave.begin();
			auto e = locator.vHave.end();

			bool first = true;
			while( i != e )
			{
				if(!first)
					out << ",\n";
				else
					first = false;
	
				out << HexStr(*i);
				++i;
			}

			out << "\n ]\n";
		}
		else if( strType == "minversion" )
		{
			int version;
			ssValue >> version;
			out << " " << version << endl;
		}
		else if( strType == "acc" )
		{
            CAccount acct;
            ssValue >> acct;
			out << " " << HexStr(acct.vchPubKey) << endl;
		}
		else if( strType == "issuer" )
		{
            CIssuer issuer;
            ssValue >> issuer;

			out << " {\"pubKey\":" << HexStr(issuer.pubKey_)
				<< ", \"location\":" << issuer.location_
				<< ", \"email\":" << issuer.emailAddress_
				<< ", \"phone_number\":" << issuer.phoneNumber_
				<< "}" << endl;
		}
		else
		{
			edcLogPrintf( "Error: Unsupported key in walletdb\n" );
		}
    } 
	catch (...)
    {
        edcLogPrintf("Error getting value from wallet database cursor\n");
    }

    return true;
}

}

void CEDCWalletDB::Dump( ostream & out )
{
    try 
	{
        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            edcLogPrintf("Error getting wallet database cursor\n");
            return;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);

            int ret = ReadAtCursor(pcursor, ssKey, ssValue);

            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                edcLogPrintf("Error reading next record from wallet database\n");
                break;
            }

			string strType;
			if(!dumpKey( out, ssKey, strType ))
				break;
			out << '[' << endl;
			if(!dumpValue( out, strType, ssValue ))
				break;
			out << ']' << endl;
		}

        pcursor->close();
    }
    catch (...) 
	{
		// It is just a dump, so do not allow it to affect the process
    }
}
