// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include "edc/rpc/edcserver.h"
#include "../utilstrencodings.h"


UniValue createEquibitPoll( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"createEquibitPoll"
		);

	return NullUniValue;
}

UniValue listEquibitMailBox( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"listEquibitMailBox"
		);

	return NullUniValue;
}

UniValue getEquibitMessage( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"getEquibitMessage"
		);

	return NullUniValue;
}

UniValue sendEquibitPollResponse( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"sendEquibitPollResponse"
		);

	return NullUniValue;
}

UniValue sellEquibit( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"sellEquibit"
		);

	return NullUniValue;
}

UniValue purchaseEquibit( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"purchaseEquibit"
		);

	return NullUniValue;
}

UniValue requestEquibitValidation( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"requestEquibitValidation"
		);

	return NullUniValue;
}

UniValue announceEquibitDividend( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"announceEquibitDividend"
		);

	return NullUniValue;
}

UniValue equibitDividendPayment( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"equibitDividendPayment"
		);

	return NullUniValue;
}

UniValue assignEquibitProxy( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"assignEquibitProxy"
		);

	return NullUniValue;
}

UniValue acceptEquibitProxyRequest( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"acceptEquibitProxyRequest"
		);

	return NullUniValue;
}

UniValue assignEquibitAgent( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"assignEquibitAgent"
		);

	return NullUniValue;
}

UniValue validateEquibitBuyer( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"validateEquibitBuyer"
		);

	return NullUniValue;
}

UniValue acceptEquibitAgentRequest( const UniValue & params, bool fHelp )
{
	if( fHelp )
		throw std::runtime_error(
			"acceptEquibitAgentRequest"
		);

	return NullUniValue;
}

static const CRPCCommand commands[] =
{ // category   name                actor (function)   okSafeMode
  // ---------- ------------------- ------------------ -------------

	{ "equibit", "createEquibitPoll", 		 &createEquibitPoll,         true },
	{ "equibit", "listEquibitMailBox", 		 &listEquibitMailBox,        true },
	{ "equibit", "getEquibitMessage", 		 &getEquibitMessage,         true },
	{ "equibit", "sendEquibitPollResponse",  &sendEquibitPollResponse,   true },
	{ "equibit", "sellEquibit", 			 &sellEquibit,               true },
	{ "equibit", "purchaseEquibit", 		 &purchaseEquibit,           true },
	{ "equibit", "requestEquibitValidation", &requestEquibitValidation,  true },
	{ "equibit", "announceEquibitDividend",  &announceEquibitDividend,   true },
	{ "equibit", "equibitDividendPayment", 	 &equibitDividendPayment,    true },
	{ "equibit", "assignEquibitProxy", 		 &assignEquibitProxy,        true },
	{ "equibit", "acceptEquibitProxyRequest",&acceptEquibitProxyRequest, true },
	{ "equibit", "assignEquibitAgent", 		 &assignEquibitAgent,        true },
	{ "equibit", "validateEquibitBuyer", 	 &validateEquibitBuyer,      true },
	{ "equibit", "acceptEquibitAgentRequest",&acceptEquibitAgentRequest, true },
};

void RegisterEquibitRPCCommands( CEDCRPCTable & edcTableRPC)
{
	for( unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++ )
		edcTableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
