// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "edc/rpc/edcserver.h"
#include "../utilstrencodings.h"
#include "pubkey.h"
#include "edc/message/edcmessage.h"
#include "edc/edcnet.h"


namespace
{

UniValue broadcastMessage( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_broadcastmessage ( \"asset\" \"type\" \"message\" )\n"
			"\nArguments:\n"
			"1. \"asset\" (string) Owners of the identified asset will receive the message\n"
			"2. \"type\" (string) Type of message. Type must be one of:\n"
			"      Acquisition\n"
			"      Ask\n"
			"      Assimilation\n"
			"      Bankruptcy\n"
			"      Bid\n"
			"      BonusIssue\n"
			"      BonusRights\n"
			"      BuyBackProgram\n"
			"      CashDividend\n"
			"      CashStockOption\n"
			"      ClassAction\n"
			"      ConversionOfConvertibleBonds\n"
			"      CouponPayment\n"
			"      Delisting\n"
			"      DeMerger\n"
			"      DividendReinvestmentPlan\n"
			"      DutchAuction\n"
			"      EarlyRedemption\n"
			"      FinalRedemption\n"
			"      GeneralAnnouncement\n"
			"      InitialPublicOffering\n"
			"      Liquidation\n"
			"      Lottery\n"
			"      MandatoryExchange\n"
			"      Merger\n"
			"      MergerWithElections\n"
			"      NameChange\n"
			"      OddLotTender\n"
			"      OptionalPut\n"
			"      OtherEvent\n"
			"      PartialRedemption\n" 
			"      ParValueChange\n"
			"      ReturnOfCapital\n"
			"      ReverseStockSplit\n"
			"      RightsAuction\n"
			"      RightsIssue\n"
			"      SchemeofArrangement\n"
			"      ScripDividend\n"
			"      ScripIssue\n"
			"      Spinoff\n"
			"      SpinOffWithElections\n"
			"      StockDividend\n"
			"      StockSplit\n"
			"      SubscriptionOffer\n"
			"      Takeover\n"
			"      TenderOffer\n"
			"      VoluntaryExchange\n"
			"      WarrantExercise\n"
			"      WarrantExpiry\n"
			"      WarrantIssue\n"
			"3. \"message\"  (string) The message to be sent to the all addresses\n"
			+ HelpExampleCli( "eb_broadcastmessage", "ACME StockDividend \"A dividend of 0.032 bitcoins will be issued on March 15th\"" )
			+ HelpExampleRpc( "eb_broadcastmessage", "ACME StockDividend \"A dividend of 0.032 bitcoins will be issued on March 15th\"" )
		);

	std::string	type;	// TODO
	CKeyID		sender;	// TODO
	std::string	assetId;// TODO
	std::string	data;	// TODO
	
	CBroadcast	* msg = CBroadcast::create( type, sender, assetId, data );

	RelayUserMessage( msg );

	return NullUniValue;
}

UniValue multicastMessage( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_multicastmessage ( \"asset\" \"message\" )\n"
			"\nArguments:\n"
			"1. \"asset\" (string) The message applies to the identified asset\n"
			"2. \"type\" (string) Type of message. Type must be one of:\n"
			"        Poll\n"
			"3. \"message\"  (string) The message to be sent to the multiple addresses\n"
			+ HelpExampleCli( "eb_messagemany", "ACME Poll \"Board of directors Vote. Choose 1 for John Smith, 2 for Doug Brown\"" )
			+ HelpExampleRpc( "eb_messagemany", "ACME Poll \"Board of directors Vote. Choose 1 for John Smith, 2 for Doug Brown\"" )
		);

	std::string	type;	// TODO
	CKeyID		sender;	// TODO
	std::string	assetId;// TODO
	std::string	data;	// TODO

	CMulticast	* msg = CMulticast::create( type, sender, assetId, data );

	RelayUserMessage( msg );

	return NullUniValue;
}

UniValue message( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_message ( \"message\" \"address\" )\n"
			"\nArguments:\n"
			"1. \"address\"   (string) The destination address\n"
			"2. \"type\" (string) Type of message. Type must be one of:\n"
			"        Private\n"
			"        Vote\n"
			"3. \"message\"   (string) The message to be sent to the specified address\n"
			+ HelpExampleCli( "eb_message", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" Private "
				"\"What is your position WRT the upcomming merger?\""  )
			+ HelpExampleRpc( "eb_message", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" Vote 1" )
		);

	std::string	type = "Private";		// TODO
	CKeyID		sender;		// TODO
	CKeyID		receiver;	// TODO
	std::string	data;		// TODO

	CPeerToPeer	* msg = CPeerToPeer::create( type, sender, receiver, data );

	RelayUserMessage( msg );

	return NullUniValue;
}

static const CRPCCommand commands[] =
{ // category   name                actor (function)   okSafeMode
  // ---------- ------------------- ------------------ -------------

	{ "equibit", "eb_message", 		 	&message,         true },
	{ "equibit", "eb_multicastmessage",	&multicastMessage,true },
	{ "equibit", "eb_broadcastmessage", &broadcastMessage,true },
};

}


void edcRegisterMessagingRPCCommands( CEDCRPCTable & edcTableRPC)
{
	for( unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++ )
		edcTableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
