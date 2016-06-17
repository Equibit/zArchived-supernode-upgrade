// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int EDC_MAX_BLOCK_SIZE = 1000000;

/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int EDC_MAX_BLOCK_SIGOPS = EDC_MAX_BLOCK_SIZE/50;

/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int EDC_COINBASE_MATURITY = 100;

/** Flags for nSequence and nLockTime locks */
enum 
{
    /* Interpret sequence numbers as relative lock-time constraints. */
    EDC_LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    EDC_LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};