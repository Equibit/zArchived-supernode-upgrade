// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDC_RPCREGISTER_H
#define EDC_EDC__RPCREGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void edcRegisterBlockchainRPCCommands( CEDCRPCTable & edcTableRPC);
/** Register P2P networking RPC commands */
void edcRegisterNetRPCCommands(CEDCRPCTable &edcTableRPC);
/** Register miscellaneous RPC commands */
void edcRegisterMiscRPCCommands(CEDCRPCTable &edcTableRPC);
/** Register mining RPC commands */
void edcRegisterMiningRPCCommands(CEDCRPCTable &edcTableRPC);
/** Register raw transaction RPC commands */
void edcRegisterRawTransactionRPCCommands(CEDCRPCTable &edcTableRPC);

static inline void edcRegisterAllCoreRPCCommands(CEDCRPCTable &edcTableRPC)
{
    edcRegisterBlockchainRPCCommands(edcTableRPC);
    edcRegisterNetRPCCommands(edcTableRPC);
    edcRegisterMiscRPCCommands(edcTableRPC);
    edcRegisterMiningRPCCommands(edcTableRPC);
    edcRegisterRawTransactionRPCCommands(edcTableRPC);
}

#endif
