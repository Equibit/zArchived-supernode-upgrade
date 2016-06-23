// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "edc/rpc/edcserver.h"
#include "../utilstrencodings.h"

namespace
{

UniValue getNewIssuer( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_getnewissuer"
		);

	return NullUniValue;
}

UniValue listIssuers( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eb_listissuers"
		);

	return NullUniValue;
}

UniValue signEquibit( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"eq_signequibit"
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
