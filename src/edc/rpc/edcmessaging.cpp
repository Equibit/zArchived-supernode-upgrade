// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "edc/rpc/edcserver.h"
#include "../utilstrencodings.h"
#include "pubkey.h"
#include "edc/message/edcmessage.h"
#include "edc/edcnet.h"
#include "edc/edcbase58.h"


namespace
{

UniValue broadcastMessage( const UniValue & params, bool fHelp )
{
	if( fHelp  || params.size() != 4)
		throw std::runtime_error(
			"eb_broadcastmessage ( \"type\" \"send-address\" \"asset\" \"message\" )\n"
			"\nArguments:\n"
			"1. \"type\" (string) Type of message. Type must be one of:\n"
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
			"2. \"send-address\"   (string) The sender address\n"
			"3. \"asset\" (string) Owners of the identified asset will receive the message\n"
			"4. \"message\"  (string) The message to be sent to the all addresses\n"
			+ HelpExampleCli( "eb_broadcastmessage", "ACME StockDividend \"A dividend of 0.032 bitcoins will be issued on March 15th\"" )
			+ HelpExampleRpc( "eb_broadcastmessage", "ACME StockDividend \"A dividend of 0.032 bitcoins will be issued on March 15th\"" )
		);

	std::string	type   = params[0].get_str();
	CEDCBitcoinAddress	 sender(params[1].get_str());
	CKeyID				 senderID;
	if(!sender.GetKeyID( senderID))
	{
		std::string msg = "Invalid sender address:";
		msg += params[1].get_str();
		throw std::runtime_error( msg );
	}

	std::string	assetId= params[2].get_str();
	std::string	data   = params[3].get_str();
	
	CBroadcast	* msg = CBroadcast::create( type, senderID, assetId, data );

	RelayUserMessage( msg );

	return NullUniValue;
}

UniValue multicastMessage( const UniValue & params, bool fHelp )
{
	if( fHelp || params.size() != 3 )
		throw std::runtime_error(
			"eb_multicastmessage ( \"type\" \"send-address\" \"asset\" \"message\" )\n"
			"\nArguments:\n"
			"1. \"type\" (string) Type of message. Type must be one of:\n"
			"        Poll\n"
			"2. \"send-address\"   (string) The sender address\n"
			"3. \"asset\" (string) The message applies to the identified asset\n"
			"4. \"message\"  (string) The message to be sent to the multiple addresses\n"
			+ HelpExampleCli( "eb_messagemany", "ACME Poll \"Board of directors Vote. Choose 1 for John Smith, 2 for Doug Brown\"" )
			+ HelpExampleRpc( "eb_messagemany", "ACME Poll \"Board of directors Vote. Choose 1 for John Smith, 2 for Doug Brown\"" )
		);

	std::string	type   = params[0].get_str();
	CEDCBitcoinAddress	 sender(params[1].get_str());
	CKeyID				 senderID;
	if(!sender.GetKeyID(senderID))
	{
		std::string msg = "Invalid sender address:";
		msg += params[1].get_str();
		throw std::runtime_error( msg );
	}

	std::string	assetID= params[2].get_str();
	std::string	data   = params[3].get_str();

	CMulticast	* msg = CMulticast::create( type, senderID, assetID, data );

	RelayUserMessage( msg );

	return NullUniValue;
}

UniValue message( const UniValue & params, bool fHelp )
{
	if( fHelp  || params.size() != 4)
		throw std::runtime_error(
			"eb_message ( \"type\" \"send-address\" \"recv-address\" \"message\" )\n"
			"\nArguments:\n"
			"1. \"type\" (string) Type of message. Type must be one of:\n"
			"        Private\n"
			"        Vote\n"
			"2. \"send-address\"   (string) The sender address\n"
			"3. \"recv-address\"   (string) The receiver address\n"
			"4. \"message\"   (string) The message to be sent to the specified address\n"
			+ HelpExampleCli( "eb_message", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" Private "
				"\"What is your position WRT the upcomming merger?\""  )
			+ HelpExampleRpc( "eb_message", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" Vote 1" )
		);

	std::string	type    = params[0].get_str();
	CEDCBitcoinAddress	 sender(params[1].get_str());
	CKeyID				 senderID;
	if(!sender.GetKeyID(senderID))
	{
		std::string msg = "Invalid sender address:";
		msg += params[1].get_str();
		throw std::runtime_error( msg );
	}

	CEDCBitcoinAddress	 receiver(params[2].get_str());
	CKeyID				 receiverID;
	if(!receiver.GetKeyID(receiverID))
	{
		std::string msg = "Invalid receiver address:";
		msg += params[1].get_str();
		throw std::runtime_error( msg );
	}

	std::string	data    = params[3].get_str();

	CPeerToPeer	* msg = CPeerToPeer::create( type, senderID, receiverID, data );

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
