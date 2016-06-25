// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "edc/rpc/edcserver.h"
#include "../utilstrencodings.h"


namespace
{

UniValue messageMany( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_messagemany ( \"message\" \"{ \"address\",...}\" )\n"
			"\nArguments:\n"
			"1. \"message\"   (string) The message to be sent to the multiple addresses\n"
			"2. \"addresses\" (string) A json object with addresses\n"
			"{\n"
			"\"address\", ...\n"
			"}\n"
			+ HelpExampleCli( "eb_messagemany", "\"A dividend of 0.032 bitcoins will be issued on March 15th\" \"{\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\" }\" " )
			+ HelpExampleRpc( "eb_messagemany", "\"A dividend of 0.032 bitcoins will be issued on March 15th\" \"{\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\" }\" " )
		);

	return NullUniValue;
}

UniValue message( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_message ( \"message\" \"address\" )\n"
			"\nArguments:\n"
			"1. \"message\"   (string) The message to be sent to the multiple addresses\n"
			"2. \"address\"   (string) The destination address\n"
			+ HelpExampleCli( "eb_message", "\"A dividend of 0.032 bitcoins will be issued on March 15th\" \"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" " )
			+ HelpExampleRpc( "eb_message", "\"A dividend of 0.032 bitcoins will be issued on March 15th\" \"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"" )
		);

	return NullUniValue;
}

static const CRPCCommand commands[] =
{ // category   name                actor (function)   okSafeMode
  // ---------- ------------------- ------------------ -------------

	{ "equibit", "eb_message", 		 	&message,         true },
	{ "equibit", "eb_messagemany", 		&messageMany,     true },
};

}


void edcRegisterMessagingRPCCommands( CEDCRPCTable & edcTableRPC)
{
	for( unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++ )
		edcTableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
