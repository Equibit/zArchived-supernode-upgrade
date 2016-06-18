// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/wallet/edcwallet.h"

#include "edc/edcbase58.h"
#include "checkpoints.h"
#include "chain.h"
#include "coincontrol.h"
#include "edc/consensus/edcconsensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "edc/edcmain.h"
#include "edc/edcnet.h"
#include "edc/policy/edcpolicy.h"
#include "edc/primitives/edcblock.h"
#include "edc/primitives/edctransaction.h"
#include "script/script.h"
#include "edc/script/edcsign.h"
#include "timedata.h"
#include "edc/edctxmempool.h"
#include "edc/edcutil.h"
#include "ui_interface.h"
#include "utilmoneystr.h"
#include "edc/edcapp.h"
#include "edc/edcparams.h"
#include "edc/edcchainparams.h"

#include <assert.h>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

using namespace std;

const char * edcDEFAULT_WALLET_DAT = "edcwallet.dat";

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CEDCWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CEDCWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

const uint256 CEDCMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly
{
    bool operator()(const pair<CAmount, pair<const CEDCWalletTx*, unsigned int> >& t1,
                    const pair<CAmount, pair<const CEDCWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

std::string CEDCOutput::ToString() const
{
    return strprintf("CEDCOutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->vout[i].nValue));
}

const CEDCWalletTx* CEDCWallet::GetWalletTx(const uint256& hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return NULL;
    return &(it->second);
}

CPubKey CEDCWallet::GenerateNewKey()
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;
    secret.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CEDCWallet::GenerateNewKey(): AddKey failed");
    return pubkey;
}

bool CEDCWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted()) 
	{
        return CEDCWalletDB(strWalletFile).WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CEDCWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CEDCWalletDB(strWalletFile).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CEDCWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CEDCWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CEDCWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
//    if (!CCryptoKeyStore::edcAddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CEDCWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CEDCWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = CEDCBitcoinAddress(CScriptID(redeemScript)).ToString();
        edcLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
//    return CCryptoKeyStore::edcAddCScript(redeemScript);
}

bool CEDCWallet::AddWatchOnly(const CScript &dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CEDCWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CEDCWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CEDCWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CEDCWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CEDCWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CEDCWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                edcLogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CEDCWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CEDCWallet::SetBestChain(const CBlockLocator& loc)
{
    CEDCWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CEDCWallet::SetMinVersion(enum WalletFeature nVersion, CEDCWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CEDCWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CEDCWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CEDCWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

set<uint256> CEDCWallet::GetConflicts(const uint256& txid) const
{
    set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CEDCWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    BOOST_FOREACH(const CEDCTxIn& txin, wtx.vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
            result.insert(it->second);
    }
    return result;
}

void CEDCWallet::Flush(bool shutdown)
{
	EDCapp & theApp = EDCapp::singleton();

    theApp.bitdb().Flush(shutdown);
}

bool CEDCWallet::Verify()
{
	EDCapp & theApp = EDCapp::singleton();

    edcLogPrintf("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0));
	EDCparams & params = EDCparams::singleton();
    std::string walletFile = params.wallet;

    edcLogPrintf("Using wallet %s\n", walletFile);
    uiInterface.InitMessage(_("Verifying wallet..."));

    // Wallet file must be a plain filename without a directory
    if (walletFile != boost::filesystem::basename(walletFile) + boost::filesystem::extension(walletFile))
        return InitError(strprintf(_("Wallet %s resides outside data "
			"directory %s"), walletFile, edcGetDataDir().string()));

    if (!theApp.bitdb().Open(edcGetDataDir()))
    {
        // try moving the database env out of the way
        boost::filesystem::path pathDatabase = edcGetDataDir() / "database";
        boost::filesystem::path pathDatabaseBak = edcGetDataDir() / 
			strprintf("database.%d.bak", GetTime());

        try 
		{
            boost::filesystem::rename(pathDatabase, pathDatabaseBak);
            edcLogPrintf("Moved old %s to %s. Retrying.\n", 
				pathDatabase.string(), pathDatabaseBak.string());
        } 
		catch (const boost::filesystem::filesystem_error&) 
		{
            // failure is ok (well, not really, but it's not worse than what 
			// we started with)
        }
        
        // try again
        if (!theApp.bitdb().Open(edcGetDataDir())) 
		{
            // if it still fails, it probably means we can't even create the 
			// database env
            return InitError(strprintf(_("Error initializing wallet "
				"database environment %s!"), edcGetDataDir()));
        }
    }
    
    if (params.salvagewallet )
    {
        // Recover readable keypairs:
        if (!CEDCWalletDB::Recover(theApp.bitdb(), walletFile, true))
            return false;
    }
    
    if (boost::filesystem::exists(edcGetDataDir() / walletFile))
    {
        CEDCDBEnv::VerifyResult r = theApp.bitdb().Verify(walletFile,CEDCWalletDB::Recover);
        if (r == CEDCDBEnv::RECOVER_OK)
        {
            InitWarning(strprintf(
				_("Warning: Wallet file corrupt, data salvaged!"
                  " Original %s saved as %s in %s; if"
                  " your balance or transactions are incorrect you should"
                  " restore from a backup."),
                walletFile, "wallet.{timestamp}.bak", edcGetDataDir()));
        }
        if (r == CEDCDBEnv::RECOVER_FAIL)
            return InitError(strprintf(_("%s corrupt, salvage failed"), 
				walletFile));
    }
    
    return true;
}

void CEDCWallet::SyncMetaData(pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CEDCWalletTx* copyFrom = NULL;
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        int n = mapWallet[hash].nOrderPos;
        if (n < nMinOrderPos)
        {
            nMinOrderPos = n;
            copyFrom = &mapWallet[hash];
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CEDCWalletTx* copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CEDCWallet::IsSpent(const uint256& hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256& wtxid = it->second;
        std::map<uint256, CEDCWalletTx>::const_iterator mit = mapWallet.find(wtxid);

        if (mit != mapWallet.end()) 
		{
            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CEDCWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(make_pair(outpoint, wtxid));

    pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CEDCWallet::AddToSpends(const uint256& wtxid)
{
    assert(mapWallet.count(wtxid));
    CEDCWalletTx& thisTx = mapWallet[wtxid];
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    BOOST_FOREACH(const CEDCTxIn& txin, thisTx.vin)
        AddToSpends(txin.prevout, wtxid);
}

bool CEDCWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;
    RandAddSeedPerfmon();

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    edcLogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            assert(!pwalletdbEncryption);
            pwalletdbEncryption = new CEDCWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin()) 
			{
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
                return false;
            }
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked) 
			{
                pwalletdbEncryption->TxnAbort();
                delete pwalletdbEncryption;
            }
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit()) 
			{
                delete pwalletdbEncryption;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload the unencrypted wallet.
                assert(false);
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CEDCDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CEDCWallet::IncOrderPosNext(CEDCWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) 
	{
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } 
	else 
	{
        CEDCWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CEDCWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CEDCWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

int64_t edcGetAdjustedTime();

bool CEDCWallet::AddToWallet(const CEDCWalletTx& wtxIn, bool fFromLoadWallet, CEDCWalletDB* pwalletdb)
{
	EDCapp & theApp = EDCapp::singleton();

    uint256 hash = wtxIn.GetHash();

    if (fFromLoadWallet)
    {
        mapWallet[hash] = wtxIn;
        CEDCWalletTx& wtx = mapWallet[hash];
        wtx.BindWallet(this);
        wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));
        AddToSpends(hash);

        BOOST_FOREACH(const CEDCTxIn& txin, wtx.vin) 
		{
            if (mapWallet.count(txin.prevout.hash)) 
			{
                CEDCWalletTx& prevtx = mapWallet[txin.prevout.hash];
                if (prevtx.nIndex == -1 && !prevtx.hashUnset()) 
				{
                    MarkConflicted(prevtx.hashBlock, wtx.GetHash());
                }
            }
        }
    }
    else
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CEDCWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CEDCWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = edcGetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext(pwalletdb);
            wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (!wtxIn.hashUnset())
            {
                if (theApp.mapBlockIndex().count(wtxIn.hashBlock))
                {
                    int64_t latestNow = wtx.nTimeReceived;
                    int64_t latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        const TxItems & txOrdered = wtxOrdered;
                        for (TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CEDCWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    int64_t blocktime = theApp.mapBlockIndex()[wtxIn.hashBlock]->GetBlockTime();
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    edcLogPrintf("AddToWallet(): found %s in block %s not in index\n",
                             wtxIn.GetHash().ToString(),
                             wtxIn.hashBlock.ToString());
            }
            AddToSpends(hash);
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            // If no longer abandoned, update
            if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned())
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex))
            {
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
        }

        //// debug print
        edcLogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!pwalletdb->WriteTx(wtx))
                return false;

        // Break debit/credit balance caches:
        wtx.MarkDirty();

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
		EDCparams & params = EDCparams::singleton();
        std::string strCmd = params.walletnotify;

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(edcRunCommand, strCmd); // thread runs free
        }

    }
    return true;
}

/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 */
bool CEDCWallet::AddToWalletIfInvolvingMe(const CEDCTransaction& tx, const CEDCBlock* pblock, bool fUpdate)
{
    {
        AssertLockHeld(cs_wallet);

        if (pblock) 
		{
            BOOST_FOREACH(const CEDCTxIn& txin, tx.vin) 
			{
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) 
				{
                    if (range.first->second != tx.GetHash()) 
					{
                        edcLogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), pblock->GetHash().ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(pblock->GetHash(), range.first->second);
                    }
                    range.first++;
                }
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CEDCWalletTx wtx(this,tx);

            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(*pblock);

            // Do not flush the wallet here for performance reasons
            // this is safe, as in case of a crash, we rescan the necessary blocks on startup through our SetBestChain-mechanism
            CEDCWalletDB walletdb(strWalletFile, "r+", false);

            return AddToWallet(wtx, false, &walletdb);
        }
    }
    return false;
}

bool CEDCWallet::AbandonTransaction(const uint256& hashTx)
{
    LOCK2(EDC_cs_main, cs_wallet);

    // Do not flush the wallet here for performance reasons
    CEDCWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    // Can't mark abandoned if confirmed or in mempool
    assert(mapWallet.count(hashTx));
    CEDCWalletTx& origtx = mapWallet[hashTx];

    if (origtx.GetDepthInMainChain() > 0 || origtx.InMempool()) 
	{
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty()) 
	{
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CEDCWalletTx& wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned()) 
		{
            // If the orig tx was not in block/mempool, none of its spends can be in mempool
            assert(!wtx.InMempool());
            wtx.nIndex = -1;
            wtx.setAbandoned();
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            NotifyTransactionChanged(this, wtx.GetHash(), CT_UPDATED);

            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) 
			{
                if (!done.count(iter->second)) 
				{
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            BOOST_FOREACH(const CEDCTxIn& txin, wtx.vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }
    }

    return true;
}

void CEDCWallet::MarkConflicted(const uint256& hashBlock, const uint256& hashTx)
{
	EDCapp & theApp = EDCapp::singleton();

    LOCK2(EDC_cs_main, cs_wallet);

    int conflictconfirms = 0;
    if (theApp.mapBlockIndex().count(hashBlock)) 
	{
        CBlockIndex* pindex = theApp.mapBlockIndex()[hashBlock];
        if (theApp.chainActive().Contains(pindex)) 
		{
            conflictconfirms = -(theApp.chainActive().Height() - pindex->nHeight + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CEDCWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty()) 
	{
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CEDCWalletTx& wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();

        if (conflictconfirms < currentconfirm) 
		{
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);

            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));

            while (iter != mapTxSpends.end() && iter->first.hash == now) 
			{
                if (!done.count(iter->second)) 
				{
                     todo.insert(iter->second);
                 }
                 iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            BOOST_FOREACH(const CEDCTxIn& txin, wtx.vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }
    }
}

void CEDCWallet::SyncTransaction(const CEDCTransaction& tx, const CBlockIndex *pindex, const CEDCBlock* pblock)
{
    LOCK2(EDC_cs_main, cs_wallet);

    if (!AddToWalletIfInvolvingMe(tx, pblock, true))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
    {
        if (mapWallet.count(txin.prevout.hash))
            mapWallet[txin.prevout.hash].MarkDirty();
    }
}


isminetype CEDCWallet::IsMine(const CEDCTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CEDCWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CEDCWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                return IsMine(prev.vout[txin.prevout.n]);
        }
    }
    return ISMINE_NO;
}

CAmount CEDCWallet::GetDebit(const CEDCTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CEDCWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CEDCWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]) & filter)
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CEDCWallet::IsMine(const CEDCTxOut& txout) const
{
    return ::IsMine(*this, txout.scriptPubKey);
}

CAmount CEDCWallet::GetCredit(const CEDCTxOut& txout, const isminefilter& filter) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CEDCWallet::GetCredit(): value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CEDCWallet::IsChange(const CEDCTxOut& txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book is
    // change. That assumption is likely to break when we implement 
	// multisignature wallets that return change back into a 
	// multi-signature-protected address; a better way of identifying which 
	// outputs are 'the send' and which are 'the change' will need to be 
	// implemented (maybe extend CEDCWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CEDCWallet::GetChange(const CEDCTxOut& txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CEDCWallet::GetChange(): value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CEDCWallet::IsMine(const CEDCTransaction& tx) const
{
    BOOST_FOREACH(const CEDCTxOut& txout, tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

bool CEDCWallet::IsFromMe(const CEDCTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CEDCWallet::GetDebit(const CEDCTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error("CEDCWallet::GetDebit(): value out of range");
    }
    return nDebit;
}

CAmount CEDCWallet::GetCredit(const CEDCTransaction& tx, const isminefilter& filter) const
{
    CAmount nCredit = 0;
    BOOST_FOREACH(const CEDCTxOut& txout, tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error("CEDCWallet::GetCredit(): value out of range");
    }
    return nCredit;
}

CAmount CEDCWallet::GetChange(const CEDCTransaction& tx) const
{
    CAmount nChange = 0;
    BOOST_FOREACH(const CEDCTxOut& txout, tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error("CEDCWallet::GetChange(): value out of range");
    }
    return nChange;
}

int64_t CEDCWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CEDCWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (!hashUnset())
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashUnset())
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CEDCWalletTx::GetAmounts(list<COutputEntry>& listReceived,
                           list<COutputEntry>& listSent, CAmount& nFee, string& strSentAccount, const isminefilter& filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CEDCTxOut& txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            edcLogPrintf("CEDCWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                     this->GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

void CEDCWalletTx::GetAccountAmounts(const string& strAccount, CAmount& nReceived,
                                  CAmount& nSent, CAmount& nFee, const isminefilter& filter) const
{
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
            nSent += s.amount;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination))
            {
                map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second.name == strAccount)
                    nReceived += r.amount;
            }
            else if (strAccount.empty())
            {
                nReceived += r.amount;
            }
        }
    }
}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 */
int CEDCWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
	EDCapp & theApp = EDCapp::singleton();

    int ret = 0;
    int64_t nNow = GetTime();
    const CEDCChainParams& chainParams = edcParams();

    CBlockIndex* pindex = pindexStart;
    {
        LOCK2(EDC_cs_main, cs_wallet);

        // no need to read and scan block, if block was created before
        // our wallet birthday (as adjusted for block time variability)
        while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200)))
            pindex = theApp.chainActive().Next(pindex);

        ShowProgress(_("Rescanning..."), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        double dProgressStart = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex, false);
        double dProgressTip = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), theApp.chainActive().Tip(), false);
        while (pindex)
        {
            if (pindex->nHeight % 100 == 0 && dProgressTip - dProgressStart > 0.0)
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99, (int)((Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex, false) - dProgressStart) / (dProgressTip - dProgressStart) * 100))));

            CEDCBlock block;
            ReadBlockFromDisk(block, pindex, edcParams().GetConsensus());
            BOOST_FOREACH(CEDCTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }

            pindex = theApp.chainActive().Next(pindex);
            if (GetTime() >= nNow + 60) 
			{
                nNow = GetTime();
                edcLogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex->nHeight, Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex));
            }
        }
        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CEDCWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;
    LOCK2(EDC_cs_main, cs_wallet);
    std::map<int64_t, CEDCWalletTx*> mapSorted;

    // Sort pending wallet transactions based on their initial wallet insertion order
    BOOST_FOREACH(PAIRTYPE(const uint256, CEDCWalletTx)& item, mapWallet)
    {
        const uint256& wtxid = item.first;
        CEDCWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain();

        if (!wtx.IsCoinBase() && (nDepth == 0 && !wtx.isAbandoned())) 
		{
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
        }
    }

    // Try to add wallet transactions to memory pool
    BOOST_FOREACH(PAIRTYPE(const int64_t, CEDCWalletTx*)& item, mapSorted)
    {
        CEDCWalletTx& wtx = *(item.second);

		EDCapp & theApp = EDCapp::singleton();
        LOCK(theApp.mempool().cs);
        wtx.AcceptToMemoryPool(false, theApp.maxTxFee());
    }
}

bool CEDCWalletTx::RelayWalletTransaction()
{
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase())
    {
        if (GetDepthInMainChain() == 0 && !isAbandoned() && InMempool()) 
		{
            edcLogPrintf("Relaying wtx %s\n", GetHash().ToString());
            CFeeRate feeRate;
			EDCapp & theApp = EDCapp::singleton();
            theApp.mempool().lookupFeeRate(GetHash(), feeRate);
            RelayTransaction((CEDCTransaction)*this, feeRate);
            return true;
        }
    }
    return false;
}

set<uint256> CEDCWalletTx::GetConflicts() const
{
    set<uint256> result;
    if (pwallet != NULL)
    {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CEDCWalletTx::GetDebit(const isminefilter& filter) const
{
    if (vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CEDCWalletTx::GetCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    int64_t credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CEDCWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CEDCWalletTx::GetAvailableCredit(bool fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableCreditCached)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(hashTx, i))
        {
            const CEDCTxOut &txout = vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CEDCWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableCreditCached = nCredit;
    fAvailableCreditCached = true;
    return nCredit;
}

CAmount CEDCWalletTx::GetImmatureWatchOnlyCredit(const bool& fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CEDCWalletTx::GetAvailableWatchOnlyCredit(const bool& fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(GetHash(), i))
        {
            const CEDCTxOut &txout = vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CEDCWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CEDCWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*this);
    fChangeCached = true;
    return nChangeCached;
}

bool CEDCWalletTx::InMempool() const
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mempool().cs);
    if (theApp.mempool().exists(GetHash())) 
	{
        return true;
    }
    return false;
}

bool CEDCWalletTx::IsTrusted() const
{
	EDCparams & params = EDCparams::singleton();

    // Quick answer in most cases
    if (!CheckFinalTx(*this))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!params.spendzeroconfchange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!InMempool())
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    BOOST_FOREACH(const CEDCTxIn& txin, vin)
    {
        // Transactions not sent by us: not trusted
        const CEDCWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == NULL)
            return false;
        const CEDCTxOut& parentOut = parent->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

bool CEDCWalletTx::IsEquivalentTo(const CEDCWalletTx& tx) const
{
        CEDCMutableTransaction tx1 = *this;
        CEDCMutableTransaction tx2 = tx;
        for (unsigned int i = 0; i < tx1.vin.size(); i++) tx1.vin[i].scriptSig = CScript();
        for (unsigned int i = 0; i < tx2.vin.size(); i++) tx2.vin[i].scriptSig = CScript();
        return CEDCTransaction(tx1) == CEDCTransaction(tx2);
}

std::vector<uint256> CEDCWallet::ResendWalletTransactionsBefore(int64_t nTime)
{
    std::vector<uint256> result;

    LOCK(cs_wallet);
    // Sort them in chronological order
    multimap<unsigned int, CEDCWalletTx*> mapSorted;
    BOOST_FOREACH(PAIRTYPE(const uint256, CEDCWalletTx)& item, mapWallet)
    {
        CEDCWalletTx& wtx = item.second;
        // Don't rebroadcast if newer than nTime:
        if (wtx.nTimeReceived > nTime)
            continue;
        mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
    }
    BOOST_FOREACH(PAIRTYPE(const unsigned int, CEDCWalletTx*)& item, mapSorted)
    {
        CEDCWalletTx& wtx = *item.second;
        if (wtx.RelayWalletTransaction())
            result.push_back(wtx.GetHash());
    }
    return result;
}

void CEDCWallet::ResendWalletTransactions(int64_t nBestBlockTime)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime-5*60);
    if (!relayed.empty())
        edcLogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CEDCWallet::GetBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(EDC_cs_main, cs_wallet);
        for (map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CEDCWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

CAmount CEDCWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(EDC_cs_main, cs_wallet);
        for (map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CEDCWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

CAmount CEDCWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(EDC_cs_main, cs_wallet);
        for (map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CEDCWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CAmount CEDCWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(EDC_cs_main, cs_wallet);
        for (map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CEDCWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CEDCWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(EDC_cs_main, cs_wallet);
        for (map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CEDCWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CAmount CEDCWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(EDC_cs_main, cs_wallet);
        for (map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CEDCWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

void CEDCWallet::AvailableCoins(vector<CEDCOutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl, bool fIncludeZeroValue) const
{
    vCoins.clear();

    {
        LOCK2(EDC_cs_main, cs_wallet);
        for (map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const uint256& wtxid = it->first;
            const CEDCWalletTx* pcoin = &(*it).second;

            if (!CheckFinalTx(*pcoin))
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;

            // We should not consider coins which aren't at least in our mempool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (nDepth == 0 && !pcoin->InMempool())
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) 
			{
                isminetype mine = IsMine(pcoin->vout[i]);
                if (!(IsSpent(wtxid, i)) && mine != ISMINE_NO &&
                    !IsLockedCoin((*it).first, i) && (pcoin->vout[i].nValue > 0 || fIncludeZeroValue) &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->fAllowOtherInputs || coinControl->IsSelected(COutPoint((*it).first, i))))
                        vCoins.push_back(CEDCOutput(pcoin, i, nDepth,
                                                 ((mine & ISMINE_SPENDABLE) != ISMINE_NO) ||
                                                  (coinControl && coinControl->fAllowWatchOnly && (mine & ISMINE_WATCH_SOLVABLE) != ISMINE_NO),
                                                 (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO));
            }
        }
    }
}

static void ApproximateBestSubset(vector<pair<CAmount, pair<const CEDCWalletTx*,unsigned int> > >vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand()&1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    //Reduces the approximate best subset by removing any inputs that are smaller than the surplus of nTotal beyond nTargetValue. 
    for (unsigned int i = 0; i < vValue.size(); i++)
    {                        
        if (vfBest[i] && (nBest - vValue[i].first) >= nTargetValue )
        {
            vfBest[i] = false;
            nBest -= vValue[i].first;
        }
    }
}

bool CEDCWallet::SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, vector<CEDCOutput> vCoins,
                                 set<pair<const CEDCWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<CAmount, pair<const CEDCWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<CAmount, pair<const CEDCWalletTx*,unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(const CEDCOutput &output, vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CEDCWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        CAmount n = pcoin->vout[i].nValue;

        pair<CAmount,pair<const CEDCWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + MIN_CHANGE)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.begin(), vValue.end(), CompareValueOnly());
    std::reverse(vValue.begin(), vValue.end());
    vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else 
	{
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        edcLogPrint("selectcoins", "SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                edcLogPrint("selectcoins", "%s ", FormatMoney(vValue[i].first));
        edcLogPrint("selectcoins", "total %s\n", FormatMoney(nBest));
    }

    return true;
}

bool CEDCWallet::SelectCoins(const vector<CEDCOutput>& vAvailableCoins, const CAmount& nTargetValue, set<pair<const CEDCWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl) const
{
    vector<CEDCOutput> vCoins(vAvailableCoins);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        BOOST_FOREACH(const CEDCOutput& out, vCoins)
        {
            if (!out.fSpendable)
                 continue;
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    set<pair<const CEDCWalletTx*, uint32_t> > setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    BOOST_FOREACH(const COutPoint& outpoint, vPresetInputs)
    {
        map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CEDCWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->vout[outpoint.n].nValue;
            setPresetCoins.insert(make_pair(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (vector<CEDCOutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(make_pair(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

	EDCparams & params = EDCparams::singleton();

    bool res = nTargetValue <= nValueFromPresetInputs ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 6, vCoins, setCoinsRet, nValueRet) ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 1, vCoins, setCoinsRet, nValueRet) ||
        (params.spendzeroconfchange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, vCoins, setCoinsRet, nValueRet));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CEDCWallet::FundTransaction(CEDCMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosInOut, std::string& strFailReason, bool includeWatching, bool lockUnspents, const CTxDestination& destChange)
{
    vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector
    BOOST_FOREACH(const CEDCTxOut& txOut, tx.vout)
    {
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, false};
        vecSend.push_back(recipient);
    }

    CCoinControl coinControl;
    coinControl.destChange = destChange;
    coinControl.fAllowOtherInputs = true;
    coinControl.fAllowWatchOnly = includeWatching;
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin)
        coinControl.Select(txin.prevout);

    CEDCReserveKey reservekey(this);
    CEDCWalletTx wtx;
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosInOut, strFailReason, &coinControl, false))
        return false;

    if (nChangePosInOut != -1)
        tx.vout.insert(tx.vout.begin() + nChangePosInOut, wtx.vout[nChangePosInOut]);

    // Add new txins (keeping original txin scriptSig/order)
    BOOST_FOREACH(const CEDCTxIn& txin, wtx.vin)
    {
        if (!coinControl.IsSelected(txin.prevout))
        {
            tx.vin.push_back(txin);

            if (lockUnspents)
            {
              LOCK2(EDC_cs_main, cs_wallet);
              LockCoin(txin.prevout);
            }
        }
    }

    return true;
}

bool CEDCWallet::CreateTransaction(const vector<CRecipient>& vecSend, CEDCWalletTx& wtxNew, CEDCReserveKey& reservekey, CAmount& nFeeRet,
                                int& nChangePosInOut, std::string& strFailReason, const CCoinControl* coinControl, bool sign)
{
	EDCapp & theApp = EDCapp::singleton();

    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    BOOST_FOREACH (const CRecipient& recipient, vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CEDCMutableTransaction txNew;

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    txNew.nLockTime = theApp.chainActive().Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)theApp.chainActive().Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(EDC_cs_main, cs_wallet);
        {
			EDCapp & theApp = EDCapp::singleton();
            std::vector<CEDCOutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, coinControl);

            nFeeRet = 0;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                double dPriority = 0;

                // vouts to the payees
                BOOST_FOREACH (const CRecipient& recipient, vecSend)
                {
                    CEDCTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    if (txout.IsDust(theApp.minRelayTxFee()))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                set<pair<const CEDCWalletTx*,unsigned int> > setCoins;
                CAmount nValueIn = 0;
                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coinControl))
                {
                    strFailReason = _("Insufficient funds");
                    return false;
                }
                BOOST_FOREACH(PAIRTYPE(const CEDCWalletTx*, unsigned int) pcoin, setCoins)
                {
                    CAmount nCredit = pcoin.first->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();
                    assert(age >= 0);
                    if (age != 0)
                        age += 1;
                    dPriority += (double)nCredit * age;
                }

                const CAmount nChange = nValueIn - nValueToSelect;
                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;

                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange = GetScriptForDestination(coinControl->destChange);

                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey);
                        assert(ret); // should never fail, as we just unlocked

                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                    }

                    CEDCTxOut newTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(theApp.minRelayTxFee()))
                    {
                        CAmount nDust = newTxOut.GetDustThreshold(theApp.minRelayTxFee()) - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount)
                            {
                                txNew.vout[i].nValue -= nDust;
                                if (txNew.vout[i].IsDust(theApp.minRelayTxFee()))
                                {
                                    strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                                    return false;
                                }
                                break;
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust(theApp.minRelayTxFee()))
                    {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    }
                    else
                    {
                        if (nChangePosInOut == -1)
                        {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size()+1);
                        }
                        else if (nChangePosInOut > txNew.vout.size())
                        {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        vector<CEDCTxOut>::iterator position = txNew.vout.begin()+nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                    }
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works.
                BOOST_FOREACH(const PAIRTYPE(const CEDCWalletTx*,unsigned int)& coin, setCoins)
                    txNew.vin.push_back(CEDCTxIn(coin.first->GetHash(),coin.second,CScript(),
                                              std::numeric_limits<unsigned int>::max()-1));

                // Sign
                int nIn = 0;
                CEDCTransaction txNewConst(txNew);
                BOOST_FOREACH(const PAIRTYPE(const CEDCWalletTx*,unsigned int)& coin, setCoins)
                {
                    bool signSuccess;
                    const CScript& scriptPubKey = coin.first->vout[coin.second].scriptPubKey;
                    CScript& scriptSigRes = txNew.vin[nIn].scriptSig;
                    if (sign)
                        signSuccess = ProduceSignature(EDCTransactionSignatureCreator(this, &txNewConst, nIn, SIGHASH_ALL), scriptPubKey, scriptSigRes);
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, scriptSigRes);

                    if (!signSuccess)
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                    nIn++;
                }

                unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (!sign) 
				{
                    BOOST_FOREACH (CEDCTxIn& vin, txNew.vin)
                        vin.scriptSig = CScript();
                }

                // Embed the constructed transaction data in wtxNew.
                *static_cast<CEDCTransaction*>(&wtxNew) = CEDCTransaction(txNew);

                // Limit size
                if (nBytes >= MAX_STANDARD_TX_SIZE)
                {
                    strFailReason = _("Transaction too large");
                    return false;
                }

                dPriority = wtxNew.ComputePriority(dPriority, nBytes);

				EDCapp & theApp = EDCapp::singleton();
				EDCparams & params = EDCparams::singleton();

                // Can we complete this as a free transaction?
                if (params.sendfreetransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE)
                {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = theApp.mempool().estimateSmartPriority(params.txconfirmtarget);
                    // Require at least hard-coded AllowFree.
                    if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                        break;
                }

                CAmount nFeeNeeded = GetMinimumFee(nBytes, params.txconfirmtarget, theApp.mempool());
                if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) 
				{
                    nFeeNeeded = coinControl->nMinimumTotalFee;
                }

                // If we made it here and we aren't even able to meet the relay
				// fee on the next pass, give up because we must be at the 
				// maximum allowed fee.
                if (nFeeNeeded < theApp.minRelayTxFee().GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }

    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CEDCWallet::CommitTransaction(CEDCWalletTx& wtxNew, CEDCReserveKey& reservekey)
{
    {
        LOCK2(EDC_cs_main, cs_wallet);
        edcLogPrintf("CommitTransaction:\n%s", wtxNew.ToString());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CEDCWalletDB* pwalletdb = fFileBacked ? new CEDCWalletDB(strWalletFile,"r+") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew, false, pwalletdb);

            // Notify that old coins are spent
            set<CEDCWalletTx*> setCoins;
            BOOST_FOREACH(const CEDCTxIn& txin, wtxNew.vin)
            {
                CEDCWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        if (fBroadcastTransactions)
        {
            // Broadcast
			EDCapp & theApp = EDCapp::singleton();
            if (!wtxNew.AcceptToMemoryPool(false, theApp.maxTxFee()))
            {
                // This must not fail. The transaction has already been signed and recorded.
                edcLogPrintf("CommitTransaction(): Error: Transaction not valid\n");
                return false;
            }
            wtxNew.RelayWalletTransaction();
        }
    }
    return true;
}

bool CEDCWallet::AddAccountingEntry(const CAccountingEntry& acentry, CEDCWalletDB & pwalletdb)
{
    if (!pwalletdb.WriteAccountingEntry_Backend(acentry))
        return false;

    laccentries.push_back(acentry);
    CAccountingEntry & entry = laccentries.back();
    wtxOrdered.insert(make_pair(entry.nOrderPos, TxPair((CEDCWalletTx*)0, &entry)));

    return true;
}

CAmount CEDCWallet::GetRequiredFee(unsigned int nTxBytes)
{
	EDCapp & theApp = EDCapp::singleton();
    return std::max(minTxFee.GetFee(nTxBytes), theApp.minRelayTxFee().GetFee(nTxBytes));
}

CAmount CEDCWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CEDCTxMemPool& pool)
{
	EDCapp & theApp = EDCapp::singleton();

    // payTxFee is user-set "I want to pay this much"
    CAmount nFeeNeeded = theApp.payTxFee().GetFee(nTxBytes);

    // User didn't set: use -txconfirmtarget to estimate...
    if (nFeeNeeded == 0) 
	{
        int estimateFoundTarget = nConfirmTarget;
        nFeeNeeded = pool.estimateSmartFee(nConfirmTarget, &estimateFoundTarget).GetFee(nTxBytes);
        // ... unless we don't have enough mempool data for estimatefee, then use fallbackFee
        if (nFeeNeeded == 0)
            nFeeNeeded = fallbackFee.GetFee(nTxBytes);
    }
    // prevent user from paying a fee below edcminRelayTxFee or minTxFee
    nFeeNeeded = std::max(nFeeNeeded, GetRequiredFee(nTxBytes));

    // But always obey the maximum
    if (nFeeNeeded > theApp.maxTxFee() )
        nFeeNeeded = theApp.maxTxFee();
    return nFeeNeeded;
}

DBErrors CEDCWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CEDCWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CEDCDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

// TODO:
//    uiInterface.LoadWallet(this);

    return DB_LOAD_OK;
}

DBErrors CEDCWallet::ZapSelectTx(vector<uint256>& vHashIn, vector<uint256>& vHashOut)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapSelectTxRet = CEDCWalletDB(strWalletFile,"cr+").ZapSelectTx(this, vHashIn, vHashOut);
    if (nZapSelectTxRet == DB_NEED_REWRITE)
    {
        if (CEDCDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapSelectTxRet != DB_LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DB_LOAD_OK;

}

DBErrors CEDCWallet::ZapWalletTx(std::vector<CEDCWalletTx>& vWtx)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CEDCWalletDB(strWalletFile,"cr+").ZapWalletTx(this, vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (CEDCDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}


bool CEDCWallet::SetAddressBook(const CTxDestination& address, const string& strName, const string& strPurpose)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW) );
    if (!fFileBacked)
        return false;
    if (!strPurpose.empty() && !CEDCWalletDB(strWalletFile).WritePurpose(CEDCBitcoinAddress(address).ToString(), strPurpose))
        return false;
    return CEDCWalletDB(strWalletFile).WriteName(CEDCBitcoinAddress(address).ToString(), strName);
}

bool CEDCWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        if(fFileBacked)
        {
            // Delete destdata tuples associated with address
            std::string strAddress = CEDCBitcoinAddress(address).ToString();
            BOOST_FOREACH(const PAIRTYPE(string, string) &item, mapAddressBook[address].destdata)
            {
                CEDCWalletDB(strWalletFile).EraseDestData(strAddress, item.first);
            }
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    if (!fFileBacked)
        return false;
    CEDCWalletDB(strWalletFile).ErasePurpose(CEDCBitcoinAddress(address).ToString());
    return CEDCWalletDB(strWalletFile).EraseName(CEDCBitcoinAddress(address).ToString());
}

bool CEDCWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CEDCWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys 
 */
bool CEDCWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CEDCWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

		EDCparams & params = EDCparams::singleton();
        int64_t nKeys = max(params.keypool, (int64_t)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        edcLogPrintf("CEDCWallet::NewKeyPool wrote %d new keys\n", nKeys);
    }
    return true;
}

bool CEDCWallet::TopUpKeyPool(unsigned int kpSize)
{
	EDCparams & params = EDCparams::singleton();
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CEDCWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = max(params.keypool, (int64_t) 0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool(): writing generated key failed");
            setKeyPool.insert(nEnd);
            edcLogPrintf("keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CEDCWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CEDCWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool(): read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        edcLogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CEDCWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CEDCWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    edcLogPrintf("keypool keep %d\n", nIndex);
}

void CEDCWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    edcLogPrintf("keypool return %d\n", nIndex);
}

bool CEDCWallet::GetKeyFromPool(CPubKey& result)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CEDCWallet::GetOldestKeyPoolTime()
{
    LOCK(cs_wallet);

    // if the keypool is empty, return <NOW>
    if (setKeyPool.empty())
        return GetTime();

    // load oldest key from keypool, get time and return
    CKeyPool keypool;
    CEDCWalletDB walletdb(strWalletFile);
    int64_t nIndex = *(setKeyPool.begin());
    if (!walletdb.ReadPool(nIndex, keypool))
        throw runtime_error("GetOldestKeyPoolTime(): read oldest key in keypool failed");
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

std::map<CTxDestination, CAmount> CEDCWallet::GetAddressBalances()
{
    map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CEDCWalletTx) walletEntry, mapWallet)
        {
            CEDCWalletTx *pcoin = &walletEntry.second;

            if (!CheckFinalTx(*pcoin) || !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CEDCWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CEDCWalletTx) walletEntry, mapWallet)
    {
        CEDCWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CEDCTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               BOOST_FOREACH(CEDCTxOut txout, pcoin->vout)
                   if (IsChange(txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CEDCWallet::GetAccountAddresses(const std::string& strAccount) const
{
    LOCK(cs_wallet);
    set<CTxDestination> result;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CEDCReserveKey::GetReservedKey(CPubKey& pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);

        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else 
		{
            return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CEDCReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CEDCReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CEDCWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CEDCWalletDB walletdb(strWalletFile);

    LOCK2(EDC_cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes(): read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes(): unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CEDCWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CEDCWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

void CEDCWallet::GetScriptForMining(boost::shared_ptr<CReserveScript> &script)
{
    boost::shared_ptr<CEDCReserveKey> rKey(new CEDCReserveKey(this));
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;

    script = rKey;
    script->reserveScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
}

void CEDCWallet::LockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CEDCWallet::UnlockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CEDCWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CEDCWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CEDCWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) 
	{
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void> 
{
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) 
	{
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) 
		{
            BOOST_FOREACH(const CTxDestination &dest, vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) 
	{
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId) 
	{
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CNoDestination &none) {}
};

void CEDCWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const 
{
	EDCapp & theApp = EDCapp::singleton();

    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = theApp.chainActive()[std::max(0, theApp.chainActive().Height() - 144)]; // the tip can be reorganised; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) 
	{
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CEDCWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) 
	{
        // iterate over all wallet transactions...
        const CEDCWalletTx &wtx = (*it).second;
        BlockMap::const_iterator blit = theApp.mapBlockIndex().find(wtx.hashBlock);

        if (blit != theApp.mapBlockIndex().end() && theApp.chainActive().Contains(blit->second)) 
		{
            // ... which are already in a block
            int nHeight = blit->second->nHeight;

            BOOST_FOREACH(const CEDCTxOut &txout, wtx.vout) 
			{
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) 
				{
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off
}

bool CEDCWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    if (!fFileBacked)
        return true;
    return CEDCWalletDB(strWalletFile).WriteDestData(CEDCBitcoinAddress(dest).ToString(), key, value);
}

bool CEDCWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    if (!fFileBacked)
        return true;
    return CEDCWalletDB(strWalletFile).EraseDestData(CEDCBitcoinAddress(dest).ToString(), key);
}

bool CEDCWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CEDCWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if(i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if(j != i->second.destdata.end())
        {
            if(value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

std::string CEDCWallet::GetWalletHelpString(bool showDebug)
{
	EDCapp & theApp = EDCapp::singleton();

    std::string strUsage = HelpMessageGroup(_("Equibit Wallet options:"));
    strUsage += HelpMessageOpt("-eb_disablewallet", _("Do not load the wallet and disable wallet RPC calls"));
    strUsage += HelpMessageOpt("-eb_keypool=<n>", strprintf(_("Set key pool size to <n> (default: %u)"), DEFAULT_KEYPOOL_SIZE));
    strUsage += HelpMessageOpt("-eb_fallbackfee=<amt>", strprintf(_("A fee rate (in %s/kB) that will be used when fee estimation has insufficient data (default: %s)"),
                                                               CURRENCY_UNIT, FormatMoney(DEFAULT_FALLBACK_FEE)));
    strUsage += HelpMessageOpt("-eb_mintxfee=<amt>", strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for transaction creation (default: %s)"),
                                                            CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MINFEE)));
    strUsage += HelpMessageOpt("-eb_paytxfee=<amt>", strprintf(_("Fee (in %s/kB) to add to transactions you send (default: %s)"),
                                                            CURRENCY_UNIT, FormatMoney(theApp.payTxFee().GetFeePerK())));
    strUsage += HelpMessageOpt("-eb_rescan", _("Rescan the block chain for missing wallet transactions on startup"));
    strUsage += HelpMessageOpt("-eb_salvagewallet", _("Attempt to recover private keys from a corrupt wallet on startup"));
    if (showDebug)
        strUsage += HelpMessageOpt("-eb_sendfreetransactions", strprintf(_("Send transactions as zero-fee transactions if possible (default: %u)"), DEFAULT_SEND_FREE_TRANSACTIONS));
    strUsage += HelpMessageOpt("-eb_spendzeroconfchange", strprintf(_("Spend unconfirmed change when sending transactions (default: %u)"), DEFAULT_SPEND_ZEROCONF_CHANGE));
    strUsage += HelpMessageOpt("-eb_txconfirmtarget=<n>", strprintf(_("If paytxfee is not set, include enough fee so transactions begin confirmation on average within n blocks (default: %u)"), DEFAULT_TX_CONFIRM_TARGET));
    strUsage += HelpMessageOpt("-eb_upgradewallet", _("Upgrade wallet to latest format on startup"));
    strUsage += HelpMessageOpt("-eb_wallet=<file>", _("Specify wallet file (within data directory)") + " " + strprintf(_("(default: %s)"), edcDEFAULT_WALLET_DAT));
    strUsage += HelpMessageOpt("-eb_walletbroadcast", _("Make the wallet broadcast transactions") + " " + strprintf(_("(default: %u)"), EDC_DEFAULT_WALLETBROADCAST));
    strUsage += HelpMessageOpt("-eb_walletnotify=<cmd>", _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)"));
    strUsage += HelpMessageOpt("-eb_zapwallettxes=<mode>", _("Delete all wallet transactions and only recover those parts of the blockchain through -rescan on startup") +
                               " " + _("(1 = keep tx meta data e.g. account owner and payment request information, 2 = drop tx meta data)"));

    if (showDebug)
    {
        strUsage += HelpMessageGroup(_("Wallet debugging/testing options:"));

        strUsage += HelpMessageOpt("-eb_dblogsize=<n>", strprintf("Flush wallet database activity from memory to disk log every <n> megabytes (default: %u)", DEFAULT_WALLET_DBLOGSIZE));
        strUsage += HelpMessageOpt("-eb_flushwallet", strprintf("Run a thread to flush wallet periodically (default: %u)", DEFAULT_FLUSHWALLET));
        strUsage += HelpMessageOpt("-eb_privdb", strprintf("Sets the DB_PRIVATE flag in the wallet db environment (default: %u)", DEFAULT_WALLET_PRIVDB));
    }

    return strUsage;
}

bool CEDCWallet::InitLoadWallet()
{	
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();
    std::string walletFile = params.wallet;

    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector<CEDCWalletTx> vWtx;

    if ( params.zapwallettxes ) 
	{
        uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

        CEDCWallet *tempWallet = new CEDCWallet(walletFile);
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DB_LOAD_OK) 
		{
            return InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
        }

        delete tempWallet;
        tempWallet = NULL;
    }

    uiInterface.InitMessage(_("Loading wallet..."));

    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    CEDCWallet *walletInstance = new CEDCWallet(walletFile);
    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
            return InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            InitWarning(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                         " or address book entries might be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DB_TOO_NEW)
            return InitError(strprintf(_("Error loading %s: Wallet requires newer version of %s"),
                               walletFile, _(PACKAGE_NAME)));
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            return InitError(strprintf(_("Wallet needed to be rewritten: restart %s to complete"), _(PACKAGE_NAME)));
        }
        else
            return InitError(strprintf(_("Error loading %s"), walletFile));
    }

    if ( params.upgradewallet > 0 )
    {
        int nMaxVersion = params.upgradewallet;
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            edcLogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            edcLogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < walletInstance->GetVersion())
        {
            return InitError(_("Cannot downgrade wallet"));
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();

        CPubKey newDefaultKey;
        if (walletInstance->GetKeyFromPool(newDefaultKey)) 
		{
            walletInstance->SetDefaultKey(newDefaultKey);
            if (!walletInstance->SetAddressBook(walletInstance->vchDefaultKey.GetID(), "", "receive"))
                return InitError(_("Cannot write default address") += "\n");
        }

        walletInstance->SetBestChain(theApp.chainActive().GetLocator());
    }

    edcLogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);

    RegisterValidationInterface(walletInstance);

    CBlockIndex *pindexRescan = theApp.chainActive().Tip();
    if ( params.rescan )
        pindexRescan = theApp.chainActive().Genesis();
    else
    {
        CEDCWalletDB walletdb(walletFile);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = edcFindForkInGlobalIndex(theApp.chainActive(), locator);
        else
            pindexRescan = theApp.chainActive().Genesis();
    }
    if (theApp.chainActive().Tip() && theApp.chainActive().Tip() != pindexRescan)
    {
        //We can't rescan beyond non-pruned blocks, stop and throw an error
        //this might happen if a user uses a old wallet within a pruned node
        // or if he ran -disablewallet for a longer time, then decided to re-enable
		EDCapp & theApp = EDCapp::singleton();
        if (theApp.pruneMode() )
        {
            CBlockIndex *block = theApp.chainActive().Tip();
            while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->nTx > 0 && pindexRescan != block)
                block = block->pprev;

            if (pindexRescan != block)
                return InitError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
        }

        uiInterface.InitMessage(_("Rescanning..."));
        edcLogPrintf("Rescanning last %i blocks (from block %i)...\n", theApp.chainActive().Height() - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        walletInstance->ScanForWalletTransactions(pindexRescan, true);
        edcLogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
        walletInstance->SetBestChain(theApp.chainActive().GetLocator());
        nWalletDBUpdated++;

        // Restore wallet transaction metadata after -zapwallettxes=1
        if ( params.zapwallettxes != 2 )
        {
            CEDCWalletDB walletdb(walletFile);

            BOOST_FOREACH(const CEDCWalletTx& wtxOld, vWtx)
            {
                uint256 hash = wtxOld.GetHash();
                std::map<uint256, CEDCWalletTx>::iterator mi = walletInstance->mapWallet.find(hash);
                if (mi != walletInstance->mapWallet.end())
                {
                    const CEDCWalletTx* copyFrom = &wtxOld;
                    CEDCWalletTx* copyTo = &mi->second;
                    copyTo->mapValue = copyFrom->mapValue;
                    copyTo->vOrderForm = copyFrom->vOrderForm;
                    copyTo->nTimeReceived = copyFrom->nTimeReceived;
                    copyTo->nTimeSmart = copyFrom->nTimeSmart;
                    copyTo->fFromMe = copyFrom->fFromMe;
                    copyTo->strFromAccount = copyFrom->strFromAccount;
                    copyTo->nOrderPos = copyFrom->nOrderPos;
                    walletdb.WriteTx(*copyTo);
                }
            }
        }
    }
    walletInstance->SetBroadcastTransactions(params.walletbroadcast );

    theApp.walletMain( walletInstance );
    return true;
}

bool CEDCWallet::ParameterInteraction()
{
	EDCparams & params = EDCparams::singleton();

    if ( params.mintxfee.size() > 0 )
    {
        CAmount n = 0;
        if (ParseMoney( params.mintxfee, n) && n > 0)
            CEDCWallet::minTxFee = CFeeRate(n);
        else
            return InitError(AmountErrMsg("mintxfee", params.mintxfee));
    }
    if ( params.fallbackfee.size() > 0 )
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney( params.fallbackfee, nFeePerK))
            return InitError(strprintf(
				_("Invalid amount for -ebfallbackfee=<amount>: '%s'"), 
				params.fallbackfee ));
        if (nFeePerK > HIGH_TX_FEE_PER_KB)
            InitWarning(_("-eb_fallbackfee is set very high! This is the transaction fee you may pay when fee estimates are not available."));
        CEDCWallet::fallbackFee = CFeeRate(nFeePerK);
    }		

	EDCapp & theApp = EDCapp::singleton();
    if (params.paytxfee.size() > 0 )
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney( params.paytxfee, nFeePerK))
            return InitError(AmountErrMsg("paytxfee", params.paytxfee));

        if (nFeePerK > HIGH_TX_FEE_PER_KB)
            InitWarning(_("-eb_paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));

        theApp.payTxFee( CFeeRate(nFeePerK, 1000) );

        if (theApp.payTxFee() < theApp.minRelayTxFee())
        {
            return InitError(strprintf(_(
				"Invalid amount for -paytxfee=<amount>: '%s' (must be at "
				"least %s)"), params.paytxfee, 
				theApp.minRelayTxFee().ToString()));
        }
    }

    if ( params.maxtxfee > 0 )
    {
        if (params.maxtxfee > HIGH_MAX_TX_FEE)
            InitWarning(_("-eb_maxtxfee is set very high! Fees this large could be paid on a single transaction."));
        theApp.maxTxFee( params.maxtxfee);

        if (CFeeRate(theApp.maxTxFee(), 1000) < theApp.minRelayTxFee())
        {
            return InitError(strprintf(_("Invalid amount for "
				"-eb_maxtxfee=<amount>: '%s' (must be at least the minrelay "
				"fee of %s to prevent stuck transactions)"),
                params.maxtxfee, theApp.minRelayTxFee().ToString()));
        }
    }

    return true;
}

int CEDCMerkleTx::SetMerkleBranch(const CEDCBlock& block)
{
    AssertLockHeld(EDC_cs_main);

	EDCapp & theApp = EDCapp::singleton();

    CEDCBlock blockTmp;

    // Update the tx's hashBlock
    hashBlock = block.GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)block.vtx.size(); nIndex++)
        if (block.vtx[nIndex] == *(CEDCTransaction*)this)
            break;
    if (nIndex == (int)block.vtx.size())
    {
        nIndex = -1;
        edcLogPrintf("ERROR: SetMerkleBranch(): couldn't find tx in block\n");
        return 0;
    }

    // Is the tx in a block that's in the main chain
    BlockMap::iterator mi = theApp.mapBlockIndex().find(hashBlock);
    if (mi == theApp.mapBlockIndex().end())
        return 0;
    const CBlockIndex* pindex = (*mi).second;
    if (!pindex || !theApp.chainActive().Contains(pindex))
        return 0;

    return theApp.chainActive().Height() - pindex->nHeight + 1;
}

int CEDCMerkleTx::GetDepthInMainChain(const CBlockIndex* &pindexRet) const
{
	EDCapp & theApp = EDCapp::singleton();

    if (hashUnset())
        return 0;

    AssertLockHeld(EDC_cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = theApp.mapBlockIndex().find(hashBlock);
    if (mi == theApp.mapBlockIndex().end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !theApp.chainActive().Contains(pindex))
        return 0;

    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (theApp.chainActive().Height() - pindex->nHeight + 1);
}

int CEDCMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return max(0, (EDC_COINBASE_MATURITY+1) - GetDepthInMainChain());
}


bool CEDCMerkleTx::AcceptToMemoryPool(bool fLimitFree, CAmount nAbsurdFee)
{
    CValidationState state;
	EDCapp & theApp = EDCapp::singleton();
    return ::AcceptToMemoryPool(theApp.mempool(), state, *this, fLimitFree, NULL, NULL, false, nAbsurdFee);
}
