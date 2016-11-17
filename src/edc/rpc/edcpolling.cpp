// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "edc/edcapp.h"
#include "edc/edcparams.h"
#include "edc/rpc/edcserver.h"
#include "edc/wallet/edcwallet.h"
#include "edc/edcnet.h"
#include "edc/edcbase58.h"
#include "edc/edcmain.h"
#include "edc/message/edcmessage.h"


// Poll question
// Possible answers
//
UniValue edcpoll(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_poll \"address\" \"proxy-address\"\n"
            "\nAssign proxy voting privileges to specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_poll", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_poll", "\"139...301\", \"1vj4...adfv\"" )
        );

// TODO

    return NullUniValue;
}

UniValue edcvote(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_vote \"address\" \"proxy-address\"\n"
            "\nRevoke proxy voting privileges from specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_vote", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_vote", "\"139...301\", \"1vj4...adfv\"" )
        );

// TODO

    return NullUniValue;
}

namespace
{

const CRPCCommand edcCommands[] =
{ //  category     name       actor (function) okSafeMode
  //  ------------ ---------- ---------------- ----------
    { "equibit",   "eb_poll", &edcpoll,        true },
    { "equibit",   "eb_vote", &edcvote,        true },
};

}

void edcRegisterWoTRPCCommands(CEDCRPCTable & edcTableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        edcTableRPC.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
