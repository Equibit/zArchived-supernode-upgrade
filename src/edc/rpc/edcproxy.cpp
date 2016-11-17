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


namespace
{

void packStrs(
std::vector<unsigned char> & data,
		 const std::string & addr,
		 const std::string & paddr )
{
	auto alen = addr.size();
	auto plen = paddr.size();

	data.resize(alen+1+plen+1);

	auto d = data.begin();

	*d++ = alen;
	
	auto i = addr.begin();
	auto e = addr.end();

	while( i != e )
	{
		*d = *i;
		++i;
		++d;
	}

	*d++ = plen;
	
	i = paddr.begin();
	e = paddr.end();

	while( i != e )
	{
		*d = *i;
		++i;
		++d;
	}
}

void packStrs( 
std::vector<unsigned char> & data,
		 const std::string & addr,
		 const std::string & paddr,
		 const std::string & other )
{
	packStrs( data, addr, paddr );

	auto olen = other.size();

	auto dsize= data.size();
	data.resize(dsize+1+olen+1);

	auto d = data.begin() + dsize;

	*d++ = olen;
	
	auto i = other.begin();
	auto e = other.end();

	while( i != e )
	{
		*d = *i;
		++i;
		++d;
	}
}

}

UniValue edcassigngeneralproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_assigngeneralproxy \"address\" \"proxy-address\"\n"
            "\nAssign proxy voting privileges to specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_assigngeneralproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_assigngeneralproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addrStr = params[0].get_str();
    std::string paddrStr= params[1].get_str();

	EDCapp & theApp = EDCapp::singleton();

	// Save data to wallet
	bool rc;
	std::string errStr;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddGeneralProxy( addrStr, paddrStr, errStr );
    }

	if(rc)
	{
		CEDCBitcoinAddress sender(addrStr);
		CKeyID senderID;
		sender.GetKeyID(senderID);

		std::vector<unsigned char> data;
		packStrs( data, addrStr, paddrStr );

		std::string assetId;
		CBroadcast * msg = CBroadcast::create( CGeneralProxy::tag, senderID, assetId, data);

		theApp.connman()->RelayUserMessage( msg, true );
	}
	else
		throw JSONRPCError(RPC_TYPE_ERROR, errStr );

    return NullUniValue;
}

UniValue edcrevokegeneralproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw std::runtime_error(
            "eb_revokegeneralproxy \"address\" \"proxy-address\"\n"
            "\nRevoke proxy voting privileges from specified address.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_revokegeneralproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_revokegeneralproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addrStr = params[0].get_str();
    std::string paddrStr= params[1].get_str();

	EDCapp & theApp = EDCapp::singleton();

	// Save data to wallet
	bool rc;
	std::string errStr;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddGeneralProxyRevoke( addrStr, paddrStr, errStr );
    }
	if(rc)
	{
		CEDCBitcoinAddress sender(addrStr);
		CKeyID senderID;
		sender.GetKeyID(senderID);

		std::vector<unsigned char> data;
		packStrs( data, addrStr, paddrStr );

		std::string assetId;
		CBroadcast * msg = CBroadcast::create( CRevokeGeneralProxy::tag, senderID, assetId, data);

		theApp.connman()->RelayUserMessage( msg, true );
	}
	else
		throw JSONRPCError(RPC_TYPE_ERROR, errStr );

    return NullUniValue;
}

UniValue edcassignissuerproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3 )
        throw std::runtime_error(
            "eb_assignissuerproxy \"address\" \"proxy-address\" \"Issuer-address\"\n"
            "\nAssign proxy privilege on all polls from specified issuer.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "3. \"issuer-address\" (string, required) The address of the issuer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_assignissuerproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_assignissuerproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addrStr = params[0].get_str();
    std::string paddrStr= params[1].get_str();
    std::string iaddrStr= params[2].get_str();

	CEDCBitcoinAddress iaddr(iaddrStr);
    if (!iaddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	EDCapp & theApp = EDCapp::singleton();

	// Save data to wallet
	bool rc;
	std::string errStr;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddIssuerProxy( addrStr, paddrStr,iaddrStr, errStr );
    }
	if(rc)
	{
		CEDCBitcoinAddress sender(addrStr);
		CKeyID senderID;
		sender.GetKeyID(senderID);

		std::vector<unsigned char> data;
		packStrs( data, addrStr, paddrStr, iaddrStr );

		std::string assetId;
		CBroadcast * msg = CBroadcast::create( CIssuerProxy::tag, senderID, assetId, data);

		theApp.connman()->RelayUserMessage( msg, true );
	}
	else
		throw JSONRPCError(RPC_TYPE_ERROR, errStr );

    return NullUniValue;
}

UniValue edcrevokeissuerproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3 )
        throw std::runtime_error(
            "eb_revokeissuerproxy \"address\" \"proxy-address\" \"Issuer-address\"\n"
            "\nRevoke proxy privilege on all polls from specified issuer.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
            "3. \"issuer-address\" (string, required) The address of the issuer\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_revokeissuerproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_revokeissuerproxy", "\"139...301\", \"1vj4...adfv\"" )
        );


    std::string addrStr = params[0].get_str();
    std::string paddrStr= params[1].get_str();
    std::string iaddrStr= params[2].get_str();

	CEDCBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

	CEDCBitcoinAddress iaddr(iaddrStr);
    if (!iaddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	EDCapp & theApp = EDCapp::singleton();

	// Save data to wallet
	bool rc;
	std::string errStr;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddIssuerProxyRevoke( addrStr, paddrStr, iaddrStr, errStr);
    }
	if(rc)
	{
		CEDCBitcoinAddress sender(addrStr);
		CKeyID senderID;
		sender.GetKeyID(senderID);

		std::vector<unsigned char> data;
		packStrs( data, addrStr, paddrStr, iaddrStr );

		std::string assetId;
		CBroadcast * msg = CBroadcast::create( CRevokeIssuerProxy::tag, senderID, assetId, data);

		theApp.connman()->RelayUserMessage( msg, true );
	}
	else
		throw JSONRPCError(RPC_TYPE_ERROR, errStr );

    return NullUniValue;
}

UniValue edcassignpollproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3 )
        throw std::runtime_error(
            "eb_assignpollproxy \"address\" \"proxy-address\" \"poll-ID\"\n"
            "\nAssign proxy privilege to specific poll.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
			"3. \"poll-ID\"        (string, required) ID of the poll\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_assignpollproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_assignpollproxy", "\"139...301\", \"1vj4...adfv\"" )
        );

    std::string addrStr = params[0].get_str();
    std::string paddrStr= params[1].get_str();
    std::string pollID  = params[2].get_str();

	EDCapp & theApp = EDCapp::singleton();

	// Save data to wallet
	bool rc;
	std::string errStr;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddPollProxy( addrStr, paddrStr, pollID, errStr );
    }
	if(rc)
	{
		CEDCBitcoinAddress sender(addrStr);
		CKeyID senderID;
		sender.GetKeyID(senderID);

		std::vector<unsigned char> data;
		packStrs( data, addrStr, paddrStr, pollID );

		std::string assetId;
		CBroadcast * msg = CBroadcast::create( CPollProxy::tag, senderID, assetId, data);

		theApp.connman()->RelayUserMessage( msg, true );
	}
	else
		throw JSONRPCError(RPC_TYPE_ERROR, errStr );

    return NullUniValue;
}

UniValue edcrevokepollproxy(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3 )
        throw std::runtime_error(
            "eb_revokepollproxy \"address\" \"proxy-address\" \"poll-ID\"\n"
            "\nRevoke proxying privilege for specific poll.\n"
            "\nArguments:\n"
            "1. \"addr\"           (string, required) The address of user\n"
            "2. \"proxy-address\"  (string, required) The address of the proxy\n"
			"3. \"poll-ID\"        (string, required) ID of the poll\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_revokepollproxy", "\"139...301\" \"1xcc...adfv\"" )
            + HelpExampleRpc("eb_revokepollproxy", "\"139...301\", \"1vj4...adfv\"" )
        );


    std::string addrStr = params[0].get_str();
    std::string paddrStr= params[1].get_str();
    std::string pollID  = params[2].get_str();

	EDCapp & theApp = EDCapp::singleton();

	// Save data to wallet
	bool rc;
	std::string errStr;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddPollProxyRevoke( addrStr, paddrStr, pollID, errStr );
    }
	if(rc)
	{
		CEDCBitcoinAddress sender(addrStr);
		CKeyID senderID;
		sender.GetKeyID(senderID);

		std::vector<unsigned char> data;
		packStrs( data, addrStr, paddrStr, pollID );
		
		std::string assetId;
		CBroadcast * msg = CBroadcast::create( CRevokePollProxy::tag, senderID, assetId, data);

		theApp.connman()->RelayUserMessage( msg, true );
	}
	else
		throw JSONRPCError(RPC_TYPE_ERROR, errStr );

    return NullUniValue;
}


namespace
{

const CRPCCommand edcCommands[] =
{ //  category        name                     actor (function)        okSafeMode
  //  --------------- ------------------------ ----------------------  ----------
    { "equibit",      "eb_assigngeneralproxy", &edcassigngeneralproxy, true },
    { "equibit",      "eb_revokegeneralproxy", &edcrevokegeneralproxy, true },
	{ "equibit",      "eb_assignissuerproxy",  &edcassignissuerproxy,  true },
    { "equibit",      "eb_revokeissuerproxy",  &edcrevokeissuerproxy,  true },
	{ "equibit",      "eb_assignpollproxy",    &edcassignpollproxy,    true },
    { "equibit",      "eb_revokepollproxy",    &edcrevokepollproxy,    true },
};

}

void edcRegisterWoTRPCCommands(CEDCRPCTable & edcTableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        edcTableRPC.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
