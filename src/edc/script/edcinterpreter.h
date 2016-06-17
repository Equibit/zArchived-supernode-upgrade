// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_SCRIPT_EDCINTERPRETER_H
#define EDC_SCRIPT_EDCINTERPRETER_H

#include "script/interpreter.h"
#include "script/script_error.h"
#include "edc/primitives/edctransaction.h"

#include <vector>
#include <stdint.h>
#include <string>

class CPubKey;
class CScript;
class CEDCTransaction;
class uint256;

bool edcCheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror);

uint256 SignatureHash(const CScript &scriptCode, const CEDCTransaction& txTo, unsigned int nIn, int nHashType);

class EDCTransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const CEDCTransaction* txTo;
    unsigned int nIn;

protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    EDCTransactionSignatureChecker(const CEDCTransaction* txToIn, unsigned int nInIn) : txTo(txToIn), nIn(nInIn) {}
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode) const;
    bool CheckLockTime(const CScriptNum& nLockTime) const;
    bool CheckSequence(const CScriptNum& nSequence) const;
};

class EDCMutableTransactionSignatureChecker : public EDCTransactionSignatureChecker
{
private:
    const CEDCTransaction txTo;

public:
    EDCMutableTransactionSignatureChecker(const CEDCMutableTransaction* txToIn, unsigned int nInIn) : EDCTransactionSignatureChecker(&txTo, nInIn), txTo(*txToIn) {}
};

bool edcEvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror = NULL );

bool edcVerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* error = NULL);
#endif // BITCOIN_SCRIPT_INTERPRETER_H