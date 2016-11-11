// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "edc/edcapp.h"
#include "edc/edcparams.h"
#include "edc/rpc/edcserver.h"
#include "edc/wallet/edcwallet.h"


UniValue edcassigngeneralproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_assigngeneralproxy \"address\" \"proxy-address\"\n"
            "\nAn owner of a public key is requesting another user certify his pubkey.\n"
            "identification information by some other means\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The public key to be certified\n"
            "2. \"signer-address\"  (string, required) Address of the signer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_assigngeneralproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_assigngeneralproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addr = params[0].get_str();
    std::string paddr= params[1].get_str();

    EDCapp & theApp = EDCapp::singleton();

    return NullUniValue;
}

UniValue edcrevokegeneralproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_revokegeneralproxy \"address\" \"proxy-address\"\n"
            "\nAn owner of a public key is requesting another user certify his pubkey.\n"
            "identification information by some other means\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The public key to be certified\n"
            "2. \"signer-address\"  (string, required) Address of the signer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_revokegeneralproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_revokegeneralproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addr = params[0].get_str();
    std::string paddr= params[1].get_str();

    EDCapp & theApp = EDCapp::singleton();

    return NullUniValue;
}

UniValue edcassignissuerproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_assignissuerproxy \"address\" \"proxy-address\"\n"
            "\nAn owner of a public key is requesting another user certify his pubkey.\n"
            "identification information by some other means\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The public key to be certified\n"
            "2. \"signer-address\"  (string, required) Address of the signer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_assignissuerproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_assignissuerproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addr = params[0].get_str();
    std::string paddr= params[1].get_str();

    EDCapp & theApp = EDCapp::singleton();

    return NullUniValue;
}

UniValue edcrevokeissuerproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_revokeissuerproxy \"address\" \"proxy-address\"\n"
            "\nAn owner of a public key is requesting another user certify his pubkey.\n"
            "identification information by some other means\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The public key to be certified\n"
            "2. \"signer-address\"  (string, required) Address of the signer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_revokeissuerproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_revokeissuerproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addr = params[0].get_str();
    std::string paddr= params[1].get_str();

    EDCapp & theApp = EDCapp::singleton();

    return NullUniValue;
}

UniValue edcassignpollproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_assignpollproxy \"address\" \"proxy-address\"\n"
            "\nAn owner of a public key is requesting another user certify his pubkey.\n"
            "identification information by some other means\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The public key to be certified\n"
            "2. \"signer-address\"  (string, required) Address of the signer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_assignpollproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_assignpollproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addr = params[0].get_str();
    std::string paddr= params[1].get_str();

    EDCapp & theApp = EDCapp::singleton();

    return NullUniValue;
}

UniValue edcrevokepollproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_revokepollproxy \"address\" \"proxy-address\"\n"
            "\nAn owner of a public key is requesting another user certify his pubkey.\n"
            "identification information by some other means\n"
            "\nArguments:\n"
            "1. \"addr\"          (string, required) The public key to be certified\n"
            "2. \"signer-address\"  (string, required) Address of the signer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_revokepollproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_revokepollproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addr = params[0].get_str();
    std::string paddr= params[1].get_str();

    EDCapp & theApp = EDCapp::singleton();

    return NullUniValue;
}


namespace
{

const CRPCCommand edcCommands[] =
{ //  category        name                     actor (function)        okSafeMode
  //  --------------- ------------------------ ----------------------  ----------
    { "equibit",      "eb_assigngeneralproxy", &edcassigngeneralproxy, true },
    { "equibit",      "eb_revokegeneralproxy", &edcrevokegeneralproxy, true },
	{ "equibit",      "eb_assignissuerproxy",  &edcassignissuerproxy,  true },
    { "equibit",      "eb_revokeissuerproxy",  &edcrevokeissuerproxy,  true },
	{ "equibit",      "eb_assignpollproxy",    &edcassignpollproxy,    true },
    { "equibit",      "eb_revokepollproxy",    &edcrevokepollproxy,    true },
};

}

void edcRegisterWoTRPCCommands(CEDCRPCTable & edcTableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        edcTableRPC.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
