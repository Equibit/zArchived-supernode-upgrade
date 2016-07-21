// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include <vector>
#include "edc/rpc/edcserver.h"
#include "../utilstrencodings.h"
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
    if (!sender.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

	CKeyID senderID;
	if(!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

	std::string	assetId= params[2].get_str();
	std::string	data   = params[3].get_str();
	
	CBroadcast	* msg = CBroadcast::create( type, senderID, assetId, data );

	RelayUserMessage( msg );

	return NullUniValue;
}

UniValue multicastMessage( const UniValue & params, bool fHelp )
{
	if( fHelp || params.size() != 4 )
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
    if (!sender.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

	if(!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

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
    if (!sender.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

	if(!sender.GetKeyID(senderID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid sender address");

	CEDCBitcoinAddress	 receiver(params[2].get_str());
	CKeyID				 receiverID;
    if (!receiver.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid receiver address");

	if(!receiver.GetKeyID(receiverID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid receiver address");

	std::string	data    = params[3].get_str();

	CPeerToPeer	* msg = CPeerToPeer::create( type, senderID, receiverID, data );

	RelayUserMessage( msg );

	return NullUniValue;
}

inline int D(char c)	{ return c-'0'; }

bool getTime( const std::string & param, time_t & t )
{
	for( size_t i = 0; i < param.size(); ++i )
	{
		// Find the first number. 
		if( isdigit(param[i]))
		{
			const char * cp = param.c_str() + i;

			// The required syntax is:
			// YYYY-MM-DD[:HH:mm:SS]
			//
			if( isdigit(cp[0]) && isdigit(cp[1]) && isdigit(cp[2]) && isdigit(cp[3]) && 
				isdigit(cp[5]) && isdigit(cp[6]) && 
				isdigit(cp[8]) && isdigit(cp[9]))
			{
				int yr = D(cp[0])*1000 + D(cp[1])*100 + D(cp[2])*10 + D(cp[3]);
				int mn = D(cp[5])*10 + D(cp[6]);
				int dy = D(cp[8])*10 + D(cp[9]);
	
				int h;
				int m;
				int s;

				if(isdigit(cp[11]) && isdigit(cp[12]) && 
				isdigit(cp[14]) && isdigit(cp[15]) && 
				isdigit(cp[17]) && isdigit(cp[18]))
				{
					h = D(cp[11])*10 + D(cp[12]);
					m = D(cp[14])*10 + D(cp[15]);
					s = D(cp[17])*10 + D(cp[18]);
				}
				else
				{
					h = 0;
					m = 0;
					s = 0;
				}

				struct tm tm;
				tm.tm_year = yr - 1900;
				tm.tm_mon  = mn - 1;
				tm.tm_mday = dy;
				tm.tm_hour = h;
				tm.tm_min  = m;
				tm.tm_sec  = s;

				t = mktime( &tm );

				return true;
			}
		}
	}

	return false;
}

inline std::string trim(const std::string &s)
{
   auto wsfront=std::find_if_not(s.begin(),s.end(),[](int c){return std::isspace(c);});
   auto wsback=std::find_if_not(s.rbegin(),s.rend(),[](int c){return std::isspace(c);}).base();
   return (wsback<=wsfront ? std::string() : std::string(wsfront,wsback));
}

// Expected input syntax:
// (name1,name2,...)
//
bool getList( const std::string & param, std::vector<std::string> & l )
{
	size_t bPos = param.find( "(" );
	size_t ePos = param.find( ")" );

	if( bPos == std::string::npos || ePos == std::string::npos )
		return false;
	
	std::string inner = param.substr(bPos+1,ePos-bPos-1);

	while( true )
	{
		size_t cPos = inner.find( "," );

		// last one
		if( cPos == std::string::npos )
		{
			if(inner.size() > 0 )
			{
				l.push_back(trim(inner));
			}
			break;
		}	
		else if( cPos > 0 )
		{
			// ... , ...
			std::string p = trim(inner.substr(0,cPos-1));
			
			l.push_back(p);
			
			inner = inner.substr(cPos+1);
		}
		else //,...
		{
			inner = inner.substr(1);
		}
	}

	return true;
}

void getParamValues(
			  const UniValue & params,   // IN
					  time_t & from,	 // OUT
					  time_t & to,	     // OUT
	std::vector<std::string> & assets,	 // OUT
	std::vector<std::string> & types,	 // OUT
	std::vector<std::string> & senders,	 // OUT
	std::vector<std::string> & receivers // OUT
)
{
	for( size_t i = 0; i < params.size(); ++i )
	{
		std::string param = params[i].get_str();

		bool rc = false;
		if( param.substr(0,4) == "from" )
		{
			rc = getTime(param.substr(4), from );
		}
		else if( param.substr(0,2) == "to" )
		{
			rc = getTime(param.substr(2), to );
		}
		else if( param.substr(0,5) == "asset" )
		{
			rc = getList(param.substr(5), assets );
		}
		else if( param.substr(0,4) == "type" )
		{
			rc = getList(param.substr(5), types );
		}
		else if( param.substr(0,6) == "sender" )
		{
			rc = getList(param.substr(6), senders );
		}
		else if( param.substr(0,8) == "receiver" )
		{
			rc = getList(param.substr(8), receivers );
		}

		if(!rc)
		{
			std::string msg = "Unrecognized parameter [";
			msg += param;
			throw std::runtime_error( msg );
		}
	}
}

UniValue getMessages( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_listmessages ( from(date[:time]) to(date[:time]) type(name[,...]) asset(name[,...]) sender(hash[,...]) receiver(hash[,...])\n"
			"\nArguments:\n"
			"\nAll arguments are optional and can be specified in any order. The date format is of the form YYYY-MM-DD.\n"
			"The optional time format is of the form HH:MM:SS.\n" 
			"\nfrom(date[:time]) Filters messages whose time stamp is less than the specified date/time.\n"
			"to(date[:time]) Filters messages whose time stamp is greater than the specified date/time.\n"
			"type(name[,...]) Filters messages which have the specified types.\n"
			"asset(name[,..]) Filters messages which are not associated with the specified assets. This filter has no\n"
			"effect on peer-to-peer messages.\n"
			"sender(hash[,...]) Filters messages which are sent by the specified senders.\n"
			"receiver(hash[,...]) Filters peer-to-peer messages which are sent to the specified receivers.\n"
			+ HelpExampleCli( "eb_listmessages", "\"from(2016-01-01:10:10:10)\" \"asset(ACME,MSXY)\"" )
			+ HelpExampleRpc( "eb_listmessages", "\"from(2016-02-01)\", \"asset(ACME,MSYZ)\"" )
		);

	time_t from;
	time_t to;
	std::vector<std::string> assets;
	std::vector<std::string> types;
	std::vector<std::string> senders;
	std::vector<std::string> receivers;

	getParamValues(
			params,
			from,
			to,
			assets,
			types,
			senders,
			receivers );

// TODO
	
	return NullUniValue;
}

UniValue getMessage( const UniValue & params, bool fHelp )
{
	if( fHelp || params.size() != 1 )
		throw std::runtime_error(
			"eb_getmessage ( hash )\n"
			"\nArguments:\n"
			"\n1. hash - the hash of the message to be loaded\n"
			+ HelpExampleCli( "eb_getmessage", "\"c1c1d256...0983fed\"" )
			+ HelpExampleRpc( "eb_getmessage", "\"70292cde...a890192\"" )
		);

	std::string hash = params[0].get_str();

// TODO
	
	return NullUniValue;
}

UniValue deleteMessage( const UniValue & params, bool fHelp )
{
	if( fHelp || params.size() != 1 )
		throw std::runtime_error(
			"eb_deletemessage ( hash )\n"
			"\nArguments:\n"
			"\n1. hash - the hash of the message to be deleted\n"
			+ HelpExampleCli( "eb_deletemessage", "\"c1c1d256...0983fed\"" )
			+ HelpExampleRpc( "eb_deletemessage", "\"70292cde...a890192\"" )
		);

	std::string hash = params[0].get_str();

// TODO
	
	return NullUniValue;
}

UniValue deleteMessages( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_deletemessages ( from(date[:time]) to(date[:time]) type(name[,...]) asset(name[,...]) sender(hash[,...]) receiver(hash[,...])\n"
			"\nArguments:\n"
			"\nAll arguments are optional and can be specified in any order. The date format is of the form YYYY-MM-DD.\n"
			"The optional time format is of the form HH:MM:SS.\n" 
			"\nfrom(date[:time]) Deletes messages whose time stamp is greater than or equal to the specified date/time.\n"
			"to(date[:time]) Deletes messages whose time stamp is less than the specified date/time.\n"
			"type(name[,...]) Deletes messages which have the specified types.\n"
			"asset(name[,..]) Deletes messages which are not associated with the specified assets. This filter has no\n"
			"effect on peer-to-peer messages.\n"
			"sender(hash[,...]) Deletes messages which are sent by the specified senders.\n"
			"receiver(hash[,...]) Deletes peer-to-peer messages which are sent to the specified receivers.\n"
			+ HelpExampleCli( "eb_deletemessages", "\"from(2016-01-01:10:10:10)\" \"asset(ACME,MSXY)\"" )
			+ HelpExampleRpc( "eb_deletemessages", "\"from(2016-02-01)\", \"asset(ACME,MSYZ)\"" )
		);

	time_t from;
	time_t to;
	std::vector<std::string> assets;
	std::vector<std::string> types;
	std::vector<std::string> senders;
	std::vector<std::string> receivers;

	getParamValues(
			params,
			from,
			to,
			assets,
			types,
			senders,
			receivers );

// TODO
	
	return NullUniValue;
}

const CRPCCommand commands[] =
{   // category   name                  actor (function)  okSafeMode
    // ---------- --------------------- ----------------- ----------
	{ "equibit", "eb_p2pmessage", 	 	&message,         true },
	{ "equibit", "eb_multicastmessage",	&multicastMessage,true },
	{ "equibit", "eb_broadcastmessage", &broadcastMessage,true },
	{ "equibit", "eb_getmessage",       &getMessage,      true },
	{ "equibit", "eb_getmessages",      &getMessages,     true },
	{ "equibit", "eb_deletemessage",    &deleteMessage,   true },
	{ "equibit", "eb_deletemessages",   &deleteMessages,  true },
};

}

void edcRegisterMessagingRPCCommands( CEDCRPCTable & edcTableRPC)
{
	for( unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++ )
		edcTableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
