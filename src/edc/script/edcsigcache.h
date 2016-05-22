// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_SCRIPT_EDCSIGCACHE_H
#define EDC_SCRIPT_EDCSIGCACHE_H

#include "script/sigcache.h"
#include "edc/script/edcinterpreter.h"

#include <vector>

class CPubKey;

class EDCCachingTransactionSignatureChecker : public EDCTransactionSignatureChecker
{
private:
    bool store;

public:
    EDCCachingTransactionSignatureChecker(const CEDCTransaction* txToIn, unsigned int nInIn, bool storeIn=true) : EDCTransactionSignatureChecker(txToIn, nInIn), store(storeIn) {}

    bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;
};

#endif // BITCOIN_SCRIPT_SIGCACHE_H
