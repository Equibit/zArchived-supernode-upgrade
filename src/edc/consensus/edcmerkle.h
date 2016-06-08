// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDCMERKLE
#define EDC_EDCMERKLE

#include <stdint.h>
#include <vector>

#include "edc/primitives/edctransaction.h"
#include "edc/primitives/edcblock.h"
#include "uint256.h"

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 edcBlockMerkleRoot(const CEDCBlock& block, bool* mutated = NULL);

/*
 * Compute the Merkle branch for the tree of transactions in a block, for a
 * given position.
 * This can be verified using ComputeMerkleRootFromBranch.
 */
std::vector<uint256> edcBlockMerkleBranch(const CEDCBlock& block, uint32_t position);

#endif
