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


// Sender
// Poll question
// Possible answers: comma separated list of answers
//
UniValue edcpoll(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3 )
        throw std::runtime_error(
            "eb_poll \"address\" \"poll-question\" \"list-of-responses\"\n"
            "\nAssign proxy voting privileges to specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"              (string, required) The address of issuer creating the poll\n"
			"2. \"asset id\"          (string, required) The ID of the asset corresponding to the poll\n"
            "3. \"polling question\"  (string, required) The address of the proxy\n"
            "4. \"valid responses\"   (string, required) Comma separated list of valid responses\n"
            "\nResult: Unique poll ID\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_poll", "\"139...301\" \"Please vote for the new board member\" \"Mary Smith,John Black\"" )
            + HelpExampleRpc("eb_poll", "\"139...301\", \"Please vote for the new board member\", \"Mary Smyth,John Black\"" )
        );

	std::string address = params[0].get_str();
	std::string question= params[1].get_str();
	std::string answers = params[2].get_str();

// TODO: edcpoll()

//	TODO: Create Poll
//	TODO: Broadcast Poll

    return NullUniValue;
}

UniValue edcvote(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3 )
        throw std::runtime_error(
            "eb_vote \"address\" \"issuer-address\" \"response\"\n"
            "\nRevoke proxy voting privileges from specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The address of sender\n"
            "2. \"iaddr\"         (string, required) The address of issuer of poll\n"
            "3. \"response\"      (string, required) The address of the proxy\n"
			"4. \"proxied addr\"  (string, optional) The proxied address\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_vote", "\"139...301\" \"1xcc...adfv\" \"John Black\"" )
            + HelpExampleRpc("eb_vote", "\"139...301\", \"1vj4...adfv\" \"Mary Smyth\"" )
        );

	std::string address = params[0].get_str();
	std::string iAddress= params[1].get_str();
	std::string response= params[2].get_str();

// TODO: edcvote()
// TODO: If poll is local, add vote

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
