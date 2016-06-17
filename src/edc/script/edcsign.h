// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_SCRIPT_EDCSIGN_H
#define EDC_SCRIPT_EDCSIGN_H

#include "script/sign.h"
#include "edc/script/edcinterpreter.h"

class CKeyID;
class CKeyStore;
class CScript;
class CEDCTransaction;

struct CEDCMutableTransaction;

/** A signature creator for transactions. */
class EDCTransactionSignatureCreator : public BaseSignatureCreator {
    const CEDCTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    const EDCTransactionSignatureChecker checker;

public:
    EDCTransactionSignatureCreator(const CKeyStore* keystoreIn, const CEDCTransaction* txToIn, unsigned int nInIn, int nHashTypeIn=SIGHASH_ALL);
    const BaseSignatureChecker& Checker() const { return checker; }
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const;
};

/** Produce a script signature for a transaction. */
bool SignSignature(const CKeyStore& keystore, const CScript& fromPubKey, CEDCMutableTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL);
bool SignSignature(const CKeyStore& keystore, const CEDCTransaction& txFrom, CEDCMutableTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL);

/** Combine two script signatures on transactions. */
CScript edcCombineSignatures(const CScript& scriptPubKey, const CEDCTransaction& txTo, unsigned int nIn, const CScript& scriptSig1, const CScript& scriptSig2);

#endif // BITCOIN_SCRIPT_SIGN_H