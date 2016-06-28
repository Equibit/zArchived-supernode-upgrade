// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "edc/rpc/edcserver.h"
#include "edc/wallet/edcwallet.h"
#include "edc/edcapp.h"
#include "edc/edcbase58.h"
#include "edc/edcmain.h"
#include "../utilstrencodings.h"

bool edcEnsureWalletIsAvailable(bool avoidException);

namespace
{

UniValue getNewIssuer( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

   if (!edcEnsureWalletIsAvailable(fHelp))
        return NullUniValue;

	if( fHelp || params.size() < 4 )
		throw std::runtime_error(
			"eb_getnewissuer( \"name\" \"location\" \"phone-number\" \"e-mail address\" )\n"
			"\nCreates a new Issuer.\n"
			"\nResult:\n"
			"The address associated with the Issuer.\n"
			"\nArguments:\n"
			"1. \"Name\"            (string) The name of the Issuer.\n"
			"2. \"Location\"        (string) The geographic address of the Issuer.\n"
			"3. \"Phone number\"    (string) The phone number of the Issuer.\n"
			"4. \"E-mail address\"  (string) The e-mail address of the Issuer.\n"
			+ HelpExampleCli( "eb_getnewissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"" )
			+ HelpExampleRpc( "eb_getnewissuer", "\"Equibit Issuer\" \"100 University Ave, Toronto\" \"416 233-4753\" \"equibit-issuer.com\"" )
		);

	std::string name       = params[0].get_str();
	std::string location   = params[1].get_str();
	std::string phoneNumber= params[2].get_str();
	std::string emailAddr  = params[3].get_str();

	CIssuer	issuer(location, phoneNumber, emailAddr);

    LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

    if (!theApp.walletMain()->IsLocked())
        theApp.walletMain()->TopUpKeyPool();

	if (!theApp.walletMain()->GetKeyFromPool(issuer.pubKey_))
		throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	walletdb.WriteIssuer( name, issuer );

	UniValue ret(UniValue::VSTR);

    ret = CEDCBitcoinAddress(issuer.pubKey_.GetID()).ToString();

    return ret;
}

UniValue listIssuers( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_listissuers\n"
			"\nLists all known Issuers.\n"
			"\nResult:\n"
			"{                                 (json object)\n"
			"  \"issuer\" : {                  (json object)\n"
			"    \"name\": name,               (string) name of the issuer\n"
			"    \"location\": location,       (string) geographic address of the issuer\n"
			"    \"phone\": phone-number,      (string) phone number of the issuer\n"
			"    \"e-mail\": e-mail-address,   (string) e-mail address of the issuer\n"
			"    \"address\": address,         (string) equibit address of the issuer\n"
			"  }, ...\n"
			"}\n"
			+ HelpExampleCli( "eb_listissuers", "" )
			+ HelpExampleRpc( "eb_listissuers", "" )
		);

	return NullUniValue;
}

UniValue signEquibit( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eq_signequibit( \"signature\" \"transaction-id\" transaction-offset )\n"
			"\nSigns an Eqibit.\n"
			"\nArguments:\n"
			"1. \"Signature\"             (string) The signature to be applied to the Equibit.\n"
			"2. \"transaction-id\"        (string) The address of the transaction that contains the output transaction.\n"
			"3. \"transaction-off\"       (string) The offset of the TxOut within that stores the Equibit to be signed.\n"
			+ HelpExampleCli( "eb_signequibit", "\"ABC Comp\" \"a3b65445c098654c4cb09736fed9232157098743ecdfa2fd403509876524edfe\" 2" )
			+ HelpExampleRpc( "eb_signequibit", "\"ABC Comp\" \"a3b65445c098654c4cb09736fed9232157098743ecdfa2fd403509876524edfe\" 2" )
		);

	return NullUniValue;
}

const CRPCCommand commands[] =
{ // category   name                actor (function)   okSafeMode
  // ---------- ------------------- ------------------ -------------

	{ "equibit", "eb_getnewissuer",		 &getNewIssuer,      true },
	{ "equibit", "eb_listissuers",		 &listIssuers,       true },
	{ "equibit", "eb_signequibit", 		 &signEquibit,       true },
};

}

void edcRegisterIssuerRPCCommands( CEDCRPCTable & edcTableRPC)
{
	for( unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++ )
		edcTableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
