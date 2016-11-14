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


#ifdef USE_HSM
#include "Thales/interface.h"
#include <secp256k1.h>

namespace
{
secp256k1_context   * secp256k1_context_verify;

struct Verifier
{
    Verifier()
    {
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    }
    ~Verifier()
    {
        secp256k1_context_destroy(secp256k1_context_verify);
    }
};

Verifier    verifier;

}

#endif


namespace
{

std::string timeStamp( )
{
	struct timespec ts;
	clock_gettime( CLOCK_REALTIME, &ts );

	char buff[32];
	strftime(buff, 20, "%Y-%m-%d %H:%M:%S", localtime(&ts.tv_sec));
	sprintf( buff+19, " %ld", ts.tv_nsec );

	return buff;
}

void signCertificate(
					EDCapp & theApp,
				 EDCparams & theParams,
			   CHashWriter & ss,
		 			CKeyID & keyID,
std::vector<unsigned char> & signature
	)
{
    CKey key;
    if(theApp.walletMain()->GetKey( keyID, key))
    {
        if (!key.Sign(ss.GetHash(), signature ))
             throw JSONRPCError(RPC_MISC_ERROR, "Sign failed");
    }
    else    // else, attempt to use HSM key
    {
#ifdef USE_HSM
        if( theParams.usehsm )
        {
            std::string hsmID;
            if(theApp.walletMain()->GetHSMKey(keyID, hsmID ))
            {
                if (!NFast::sign( *theApp.nfHardServer(), *theApp.nfModule(),
                hsmID, ss.GetHash().begin(), 256, signature ))
                    throw JSONRPCError( RPC_MISC_ERROR, "Sign failed");

                secp256k1_ecdsa_signature sig;
                memcpy( sig.data, signature.data(), sizeof(sig.data));

            	secp256k1_ecdsa_signature_normalize( secp256k1_context_verify, &sig, &sig );

           		signature.resize(72);
           		size_t nSigLen = 72;

            	secp256k1_ecdsa_signature_serialize_der( secp256k1_context_verify,
                                       (unsigned char*)&signature[0], &nSigLen, &sig );
               	signature.resize(nSigLen);
               	signature.push_back((unsigned char)SIGHASH_ALL);
            }
            else
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not refer to key");
        }
        else
            throw JSONRPCError(RPC_MISC_ERROR, "Error: HSM processing disabled. "
                "Use -eb_usehsm command line option to enable HSM processing" );
#else
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not refer to key");
#endif
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

	CEDCBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

	CEDCBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	// Contents of General Proxy 
	//
	// "General Proxy"
	// Address-of-voter
	// Address-of-Proxy-Agent
	// Creation Time Stamp

	// Create certificate hash

	std::string ts = timeStamp();
	std::string cert = "General Proxy;";
	cert += addrStr + ';' + paddrStr + ';' + ts;

	CHashWriter ss(SER_GETHASH, 0);
	ss << cert;
	
    EDCapp & theApp = EDCapp::singleton();
	EDCparams & theParams = EDCparams::singleton();

	std::vector<unsigned char> signature;
	signCertificate( theApp, theParams, ss, keyID, signature );

	// Save data to wallet
	bool rc;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddGeneralProxy( addrStr, paddrStr, cert, signature );
    }

	// TODO: Publish the message

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

	CEDCBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

	CEDCBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	// Contents of General Proxy Revoke
	//
	// "REVOKE General Proxy"
	// Address-of-voter
	// Address-of-Proxy-Agent
	// Creation Time Stamp

	// Create certificate hash

	std::string ts = timeStamp();
	std::string cert = "REVOKE General Proxy;";
	cert += addrStr + ';' + paddrStr + ';' + ts;

	CHashWriter ss(SER_GETHASH, 0);
	ss << cert;
	
    EDCapp & theApp = EDCapp::singleton();
	EDCparams & theParams = EDCparams::singleton();

	std::vector<unsigned char> signature;
	signCertificate( theApp, theParams, ss, keyID, signature );

	// Save data to wallet
	bool rc;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddGeneralProxyRevoke( addrStr, paddrStr, cert, signature );
    }
	// TODO: Publish the message

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

	CEDCBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

	CEDCBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	CEDCBitcoinAddress iaddr(iaddrStr);
    if (!iaddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	// Contents of Issuer Proxy 
	//
	// "Issuer Proxy"
	// Address-of-voter
	// Address-of-Proxy-Agent
	// Address-of-Issuer-Agent
	// Creation Time Stamp

	// Create certificate hash

	std::string ts = timeStamp();
	std::string cert = "Issuer Proxy;";
	cert += addrStr + ';' + paddrStr + ';' + iaddrStr + ';' + ts;

	CHashWriter ss(SER_GETHASH, 0);
	ss << cert;
	
    EDCapp & theApp = EDCapp::singleton();
	EDCparams & theParams = EDCparams::singleton();

	std::vector<unsigned char> signature;
	signCertificate( theApp, theParams, ss, keyID, signature );

	// Save data to wallet
	bool rc;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddIssuerProxy( addrStr, paddrStr, iaddrStr, cert, signature );
    }
	// TODO: Publish the message

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

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

	CEDCBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	CEDCBitcoinAddress iaddr(iaddrStr);
    if (!iaddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	// Contents of Issuer Proxy Revoke
	//
	// "REVOKE Issuer Proxy"
	// Address-of-voter
	// Address-of-Proxy-Agent
	// Address-of-Issuer-Agent
	// Creation Time Stamp

	// Create certificate hash

	std::string ts = timeStamp();
	std::string cert = "REVOKE Issuer Proxy;";
	cert += addrStr + ';' + paddrStr + ';' + iaddrStr + ';' + ts;

	CHashWriter ss(SER_GETHASH, 0);
	ss << cert;
	
    EDCapp & theApp = EDCapp::singleton();
	EDCparams & theParams = EDCparams::singleton();

	std::vector<unsigned char> signature;
	signCertificate( theApp, theParams, ss, keyID, signature );

	// Save data to wallet
	bool rc;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddIssuerProxyRevoke( addrStr, paddrStr, iaddrStr,cert,signature);
    }
	// TODO: Publish the message

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

	CEDCBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

	CEDCBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	// Contents of Poll Proxy 
	//
	// "Poll Proxy"
	// Address-of-voter
	// Address-of-Proxy-Agent
	// Poll
	// Creation Time Stamp

	// Create certificate hash

	std::string ts = timeStamp();
	std::string cert = "Poll Proxy;";
	cert += addrStr + ';' + paddrStr + ';' + pollID + ';' + ts;

	CHashWriter ss(SER_GETHASH, 0);
	ss << cert;
	
    EDCapp & theApp = EDCapp::singleton();
	EDCparams & theParams = EDCparams::singleton();

	std::vector<unsigned char> signature;
	signCertificate( theApp, theParams, ss, keyID, signature );

	// Save data to wallet
	bool rc;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddPollProxy( addrStr, paddrStr, pollID, cert, signature );
    }
	// TODO: Publish the message

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

	CEDCBitcoinAddress addr(addrStr);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

	CEDCBitcoinAddress paddr(paddrStr);
    if (!paddr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid proxy address");

	// Contents of Poll Proxy Revoke
	//
	// "REVOKE Poll Proxy"
	// Address-of-voter
	// Address-of-Proxy-Agent
	// Poll
	// Creation Time Stamp

	// Create certificate hash

	std::string ts = timeStamp();
	std::string cert = "REVOKE Poll Proxy;";
	cert += addrStr + ';' + paddrStr + ';' + pollID + ';' + ts;

	CHashWriter ss(SER_GETHASH, 0);
	ss << cert;
	
    EDCapp & theApp = EDCapp::singleton();
	EDCparams & theParams = EDCparams::singleton();

	std::vector<unsigned char> signature;
	signCertificate( theApp, theParams, ss, keyID, signature );

	// Save data to wallet
	bool rc;
    {
        LOCK2(EDC_cs_main, theApp.walletMain()->cs_wallet);

        edcEnsureWalletIsUnlocked();
		rc = theApp.walletMain()->AddPollProxyRevoke( addrStr, paddrStr, pollID,cert,signature);
    }
	// TODO: Publish the message

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
