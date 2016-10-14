// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "policy/policy.h"
#include "edc/consensus/edcconsensus.h"
#include "edc/script/edcinterpreter.h"
#include "script/standard.h"

#include <string>

const unsigned int EDC_MAX_STANDARD_TX_COST = 400000;

class CEDCCoinsViewCache;

    /**
     * Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
bool IsStandardTx(const CEDCTransaction& tx, std::string& reason);
    /**
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
bool AreInputsStandard(const CEDCTransaction& tx, const CEDCCoinsViewCache& mapInputs);

/** Compute the virtual transaction size (cost reinterpreted as bytes). */
int64_t edcGetVirtualTransactionSize(int64_t nCost);
int64_t edcGetVirtualTransactionSize(const CEDCTransaction & tx);

