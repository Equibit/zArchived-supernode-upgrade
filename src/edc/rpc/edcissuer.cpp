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
#include "wallet/wallet.h"


bool edcEnsureWalletIsAvailable(bool avoidException);

namespace
{

std::string edcIssuerFromValue(const UniValue& value)
{
    std::string issuer = value.get_str();
    if ( issuer == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");
    return issuer;
}

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

	CKeyID keyID = issuer.pubKey_.GetID();

	theApp.walletMain()->SetAddressBook(keyID, name, "receive");

	ret = CEDCBitcoinAddress(issuer.pubKey_.GetID()).ToString();

	return ret;
}

UniValue listIssuers( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

	if( fHelp )
		throw std::runtime_error(
			"eb_getissuers\n"
			"\nLists all known Issuers.\n"
			"\nResult:\n"
			"[                                 (json object)\n"
			"  {                               (json object)\n"
			"    \"name\": name,               (string) name of the issuer\n"
			"    \"location\": location,       (string) geographic address of the issuer\n"
			"    \"phone\": phone-number,      (string) phone number of the issuer\n"
			"    \"e-mail\": e-mail-address,   (string) e-mail address of the issuer\n"
			"    \"address\": address,         (string) equibit address of the issuer\n"
			"  }, ...\n"
			"]\n"
			+ HelpExampleCli( "eb_getissuers", "" )
			+ HelpExampleRpc( "eb_getissuers", "" )
		);

	CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	std::vector<std::pair<std::string,CIssuer>>	issuers;
	walletdb.ListIssuers( issuers );

	std::vector<std::pair<std::string, CIssuer>>::iterator i = issuers.begin();
	std::vector<std::pair<std::string, CIssuer>>::iterator e = issuers.end();
	
	std::stringstream out;
	out << "[\n";

	bool first = true;
	while( i != e )
	{
		const std::string & name = i->first;
		const CIssuer & issuer = i->second;

		if(!first)
			out << ",\n";
		else
			first = false;

		out << "  {"
            << "\"name\": \"" << name << "\""
			<< ", \"pubKey\":\"" << HexStr(issuer.pubKey_) << "\""
            << ", \"location\":\"" << issuer.location_ << "\""
            << ", \"email\":\"" << issuer.emailAddress_ << "\""
            << ", \"phone_number\":\"" << issuer.phoneNumber_ << "\""
		    << "}";

		++i;
	}
	out << "\n]";

	UniValue ret(UniValue::VSTR, out.str());

	return ret;
}

UniValue authorizeEquibit( const UniValue & params, bool fHelp )
{
	EDCapp & theApp = EDCapp::singleton();

	if (!edcEnsureWalletIsAvailable(fHelp))
	    return NullUniValue;

	if( fHelp || params.size() < 3)
		throw std::runtime_error(
			"eq_authorizeequibit( \"issuer\" \"transaction-id\" transaction-offset )\n"
			"\nSigns an Eqibit.\n"
			"\nArguments:\n"
			"1. \"Issuer\"                (string) The issuer that will be authorizing the Equibit.\n"
			"2. \"transaction-id\"        (string) The address of the transaction that contains the output transaction.\n"
			"3. \"transaction-off\"       (string) The offset of the TxOut within that stores the Equibit to be authorized.\n"
	        "\nResult:\n"
	        "\"transactionid\"            (string) The transaction id.\n"

			+ HelpExampleCli( "eb_authorizeequibit", "\"ABC Comp\" \"a3b65445c098654c4cb09736fed9232157098743ecdfa2fd403509876524edfe\" 2" )
			+ HelpExampleRpc( "eb_authorizeequibit", "\"ABC Comp\" \"a3b65445c098654c4cb09736fed9232157098743ecdfa2fd403509876524edfe\" 2" )
		);
	LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

	std::string iName = edcIssuerFromValue(params[0]);
	std::string txID  = params[1].get_str();
	unsigned	txOff = params[2].get_int();

	edcEnsureWalletIsUnlocked();

	CEDCWalletDB walletdb(theApp.walletMain()->strWalletFile);

	// Get issuer address
	CIssuer issuer;
	if( !walletdb.ReadIssuer( iName, issuer ) )
        throw JSONRPCError(RPC_WALLET_INVALID_ISSUER_NAME, "Invalid issuer name");
		
	CKeyID id = issuer.pubKey_.GetID();
	CTxDestination address = CEDCBitcoinAddress(id).Get();

	// Get the transaction and txOut from params
    uint256 hash;
    hash.SetHex(txID);

    if (!theApp.walletMain()->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CEDCWalletTx& wtx = theApp.walletMain()->mapWallet[hash];

	if(wtx.vout.size() <= txOff )
        throw JSONRPCError(RPC_WALLET_ERROR, "TxOut offset is out of range" );

	// Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CEDCReserveKey reservekey(theApp.walletMain());
    std::string strError;

	CEDCWalletTx wtxNew;

    if (!theApp.walletMain()->CreateAuthorizingTransaction( issuer, wtx, txOff, wtxNew, reservekey, strError))
    {
#if HANDLE_FEE
        if (nValue > theApp.walletMain()->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(0));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
#endif
    }

    if (!theApp.walletMain()->CommitTransaction(wtxNew, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR,"Error: The transaction was rejected! This might happen if some of the "
											"coins in your wallet were already spent, such as if you used a copy of "
											"the wallet and coins were spent in the copy but not marked as spent here.");

	return wtxNew.GetHash().GetHex();
}

const CRPCCommand commands[] =
{ // category   name                actor (function)   okSafeMode
  // ---------- ------------------- ------------------ -------------

	{ "equibit", "eb_getnewissuer",		 &getNewIssuer,      true },
	{ "equibit", "eb_getissuers",		 &listIssuers,       true },
	{ "equibit", "eb_authorizeequibit",  &authorizeEquibit,  true },
};

}

void edcRegisterIssuerRPCCommands( CEDCRPCTable & edcTableRPC)
{
	for( unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++ )
		edcTableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
