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
#include "edc/rpc/edcpolling.h"


namespace
{

std::string trim( const std::string & a )
{
	std::string out;

	size_t b = 0;
	size_t e = a.size() - 1;

	while( b < e && isspace(a[b]))
		++b;
	while( e > b && isspace(a[e]))
		--e;

	return std::string( a, b, e-b+1 );
}

// 0) answers.size() > 0
// 1) It must contain at least one comma 
// 2) The first character cannot be a comma
// 3) The last character cannot be a comma
// 4) No two commas are adjacent (ie. no value is empty)
//
bool validAnswers( 
		const std::string & answers, 
 std::vector<std::string> & ansVec )
{
	if( answers.size() == 0 ||
	answers[0] == ',' ||
	answers[answers.size()-1] == ',' ||
	answers.find(',') == std::string::npos )
		return false;

	auto i = answers.begin();
	auto e = answers.end();

	std::string ans;

	while( i != e )
	{
		if( *i == ',' )
		{
			ans = trim(ans);
			if(ans.size() == 0 )
				return false;

			ansVec.push_back(ans);
			ans.clear();
		}
		else
			ans += *i;

		++i;
	}

	ans = trim(ans);
	if(ans.size() == 0 )
		return false;

	ansVec.push_back(ans);
	return true;
}

bool validDate( const std::string & date )
{
	// 0123456789
	// YYYY-MM-DD
	return 	isdigit(date[0]) && isdigit(date[1]) && isdigit(date[2]) && isdigit(date[3]) &&
			isdigit(date[5]) && isdigit(date[6]) &&
			isdigit(date[8]) && isdigit(date[9]);
}

}

UniValue edcpoll(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5 )
        throw std::runtime_error(
            "eb_poll \"address\" \"poll-question\" \"list-of-responses\" \"end-date\" (\"start-date\")\n"
            "\nAssign proxy voting privileges to specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"               (string, required) The address of issuer creating the poll\n"
            "2. \"polling question\"   (string, required) The address of the proxy\n"
            "3. \"list-of-responses\"  (string, required) Comma separated list of valid responses\n"
			"4. \"end-date\"           (string, required) Date on which the poll ends\n"
			"5. \"start-date\"         (string, optional) Date on which the poll starts\n"
            "\nResult: Unique poll ID\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_poll", "\"139...301\" \"Please vote for the new board member\" \"Mary Smith,John Black\" \"2017-02-28\"" )
            + HelpExampleRpc("eb_poll", "\"139...301\", \"Please vote for the new board member\", \"Mary Smyth,John Black\" \"2017-02-28\"" )
        );

	std::string address  = params[0].get_str();
	std::string question = params[1].get_str();
	std::string answers  = params[2].get_str();
	std::string endDate  = params[3].get_str();
	std::string startDate;

	if(params.size() > 4)
	{
		startDate = params[4].get_str();
	}

	CEDCBitcoinAddress  addr(address);

    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID issuerID;
    if(!addr.GetKeyID(issuerID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

	std::vector<std::string> ansVec;
	if(!validAnswers(answers, ansVec))
        throw JSONRPCError(RPC_TYPE_ERROR, "Valid poll answers parameter should be a comma separated list of at least two values");
		
	if(!validDate(endDate))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid end date. It should be of the form YYYY-MM-DD");
	
	if(startDate.size())
	{
		if(!validDate(startDate))
        	throw JSONRPCError(RPC_TYPE_ERROR, "Invalid start date. It should be of the form YYYY-MM-DD");
	}
	else
	{
		time_t t;
		struct tm ts;
		time(&t);
		localtime_r( &t, &ts);

		char buff[16];
		sprintf( buff, "%4.4d-%2.2d-%2.2d", ts.tm_year+1900, ts.tm_mon +1, ts.tm_mday );

		startDate = buff;
	}

	EDCapp & theApp = EDCapp::singleton();

	Poll poll( issuerID, question, ansVec, startDate, endDate );

	bool rc;
	{
		LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

		edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddPoll( issuerID, poll );
	}

	// Broadcast poll to the network

	if( rc )
	{
		CDataStream ssPoll(SER_NETWORK, PROTOCOL_VERSION);
		ssPoll << poll;

		std::vector<unsigned char> data;
		ssPoll >> data;

		CBroadcast * msg = CBroadcast::create( CPoll::tag, issuerID, data);
	
		theApp.connman()->RelayUserMessage( msg, true );
	}

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
            "3. \"response\"      (string, required) The poll response value\n"
			"4. \"proxied addr\"  (string, optional) The proxied address\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_vote", "\"139...301\" \"1xcc...adfv\" \"John Black\" \"1zswdc...209sf\"" )
            + HelpExampleRpc("eb_vote", "\"139...301\", \"1vj4...adfv\" \"Mary Smyth\"" )
        );

	std::string address = params[0].get_str();
	std::string iAddress= params[1].get_str();
	std::string response= params[2].get_str();

// TODO: If poll is local, add vote else send vote onto network

    return NullUniValue;
}

UniValue edcpollresults(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_pollresults \"address\" \"pollid\"\n"
            "\nReturns the results of the poll.\n"
            "\nArguments:\n"
            "1. \"address\"        (string, required) The address of poll issuer\n"
            "2. \"pollid\"         (string, required) The id of the poll\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_vote", "\"139...301\" \"1xcc...adfv\" \"John Black\"" )
            + HelpExampleRpc("eb_vote", "\"139...301\", \"1vj4...adfv\" \"Mary Smyth\"" )
        );

	std::string address = params[0].get_str();
	std::string iAddress= params[1].get_str();

// TODO: Return poll results from wallet

    return NullUniValue;
}

namespace
{

const CRPCCommand edcCommands[] =
{ //  category     name              actor (function) okSafeMode
  //  ------------ ----------------- ---------------- ----------
    { "equibit",   "eb_poll",        &edcpoll,        true },
    { "equibit",   "eb_vote",        &edcvote,        true },
	{ "equibit",   "eb_pollresults", &edcpollresults, true },
};

}

void edcRegisterWoTRPCCommands(CEDCRPCTable & edcTableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        edcTableRPC.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}

//////////////////////////////////////////////////////////////////////

namespace
{

// 0123456789
// yyyy-mm-dd
time_t toTime( const std::string & date )
{
	int y = (date[0] -'0') * 1000 + 
			(date[1] -'0') * 100 + 
			(date[2] -'0')* 10 + 
			(date[3] -'0');
	int m = (date[5] -'0') * 10 + (date[6] -'0');
	int d = (date[8] -'0') * 10 + (date[9] -'0');

	struct tm ts;
	memset( &ts, 0, sizeof(struct tm));

	ts.tm_year = y - 1900;
	ts.tm_mon  = m - 1;
	ts.tm_mday = d;

	return mktime(&ts);
}

}

Poll::Poll( 
	const CKeyID 	  & issuerID,
	const std::string & question, 
	const std::vector<std::string> & ans,
	const std::string & start,
	const std::string & end ): 
	issuerID_(issuerID), 
	question_(question), 
	answers_(ans),
	start_(toTime( start )),
	end_(toTime( end ))
{
}

bool Poll::validAnswer( const std::string & ans ) const
{
	return std::find( answers_.begin(), answers_.end(), ans ) != answers_.end();
}

bool Poll::validDate( time_t d ) const
{
	return d >= start_ && d <= end_;
}

uint160	Poll::id() const
{
}
