// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "edc/edcapp.h"
#include "edc/rpc/edcserver.h"
#include "utilstrencodings.h"


UniValue edcrequestwotcertificate(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"

            "\nResult:\n"
            "{\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("eb_signrawtransaction", "\"myhex\"")
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

UniValue edcgetwotcertificate(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"

            "\nResult:\n"
            "{\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("eb_signrawtransaction", "\"myhex\"")
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

UniValue edcrevokewotcertificate(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"

            "\nResult:\n"
            "{\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("eb_signrawtransaction", "\"myhex\"")
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

UniValue edcwotchainexists(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"

            "\nResult:\n"
            "{\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("eb_wotchainexists", "\"myhex\"")
            + HelpExampleRpc("eb_wotchainexists", "\"myhex\"")
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

namespace
{

const CRPCCommand edcCommands[] =
{ //  category              name                      actor (function)           okSafeMode
  //  --------------------- ------------------------  -----------------------    ----------
    { "equibit",         "eb_requestwotcertificate",  &edcrequestwotcertificate, true },
    { "equibit",         "eb_getwotcertificate",      &edcgetwotcertificate,     true },
    { "equibit",         "eb_revokewotcertificate",   &edcrevokewotcertificate,  true },
    { "equibit",         "eb_wotchainexits",          &edcwotchainexists,        true  },
};

}

void edcRegisterWoTRPCCommands(CEDCRPCTable & edcTableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        edcTableRPC.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
