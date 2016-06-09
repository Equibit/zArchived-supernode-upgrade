// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDC_EDC_RPCREGISTER_H
#define EDC_EDC__RPCREGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void edcRegisterBlockchainRPCCommands(CRPCTable &tableRPC);
/** Register P2P networking RPC commands */
void edcRegisterNetRPCCommands(CRPCTable &tableRPC);
/** Register miscellaneous RPC commands */
void edcRegisterMiscRPCCommands(CRPCTable &tableRPC);
/** Register mining RPC commands */
void edcRegisterMiningRPCCommands(CRPCTable &tableRPC);
/** Register raw transaction RPC commands */
void edcRegisterRawTransactionRPCCommands(CRPCTable &tableRPC);

static inline void edcRegisterAllCoreRPCCommands(CRPCTable &tableRPC)
{
    edcRegisterBlockchainRPCCommands(tableRPC);
    edcRegisterNetRPCCommands(tableRPC);
    edcRegisterMiscRPCCommands(tableRPC);
    edcRegisterMiningRPCCommands(tableRPC);
    edcRegisterRawTransactionRPCCommands(tableRPC);
}

#endif
