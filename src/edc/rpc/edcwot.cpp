// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "univalue.h"
#include "edc/edcapp.h"
#include "edc/rpc/edcserver.h"
#include "utilstrencodings.h"

/******************************************************************************
eb_requestwotcertificate

    An owner of a public key is requesting another user certify his pubkey. 
    Note that this solicitation is not required to create WoT certificates. 
    It is simply a means for the owner of the public key to notify the 
    potential signer that he wants the signer to create the certificate. If 
    this message is not sent, then the signer will have to get the 
    identification information by some other means.

    Parameters:

    1) Pubkey of to be certified. 
    2) Address of signer
    3) Name of owner of public key
    4) Physical address of owner of public key 
    5) Phone number of owner of public key 
    6) email address of owner of public key 
    7) http address of owner of public key 
    8) Expiration time of certificate in number of blocks from current block

    Return: none

    Side effects:

    - Sends request-wot-certificate message to address of signer
******************************************************************************/

UniValue edcrequestwotcertificate(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"pubkey\" \"signer-address\" \"name\" \"geo-address\" \"phone#\" \"email-addr\" \"http-addr\" ( expiration )\n"
    		"\nAn owner of a public key is requesting another user certify his pubkey.\n"
		    "Note that this solicitation is not required to create WoT certificates.\n" 
		    "It is simply a means for the owner of the public key to notify the\n" 
		    "potential signer that he wants the signer to create the certificate. If\n" 
		    "this message is not sent, then the signer will have to get the\n" 
		    "identification information by some other means\n"
            "\nArguments:\n"
    		"1. \"pubkey\"          (string, required) The public key to be certified\n"
    		"2. \"signer-address\"  (string, required) Address of the signer\n"
    		"3. \"name\"            (string, required) Name of the owner of public key\n"
    		"4. \"geo-address\"     (string, required) Geographic address of owner of public key\n"
    		"5. \"phone#\"          (string, required) Phone number of owner of public key\n"
    		"6. \"email-addr\"      (string, required) email address of owner of public key\n"
    		"7. \"http-addr\"       (string, required) http address of owner of public key\n"
    		"8. \"expiration\"      (number, optional) Expiration time of certificate, measured in number of blocks from current block\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_requestwotcertificate", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"\" \"\"" )
            + HelpExampleRpc("eb_requestwotcertificate", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"\" \"\"" )
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

/******************************************************************************
eb_getwotcertificate

    Creates a new WOT certificate

    Parameters:

    1) Pubkey of to be certified
    2) Address of signer
    3) Name of owner of public key
    4) Geographic address of owner of public key 
    5) Phone number of owner of public key 
    6) email address of owner of public key 
    7) http address of owner of public key 
    8) Name of signer
    9) Geographic address of signer 
    10) Phone number of signer 
    11) email address of signer 
    12) http address of signer 
    13) Expiration time of certificate in number of blocks from current block

    Return: None

    Side effects:

    - Creates WOT certificate. Broadcasts wot-certificate message to network 
      which contains the certificate.
    - Saves the WOT certificate to the wallet
******************************************************************************/

UniValue edcgetwotcertificate(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"pubkey\" \"address\" \"oname\" \"ogeo-addr\" \"ophone\" \"oe-mail\" \"ohttp\" \"sname\" \"sgeo-addr\" \"sphone\" \"semail\" \"shttp\" ( expire )\n"
    		"\nCreates a new WOT certificate.\n"
            "\nArguments:\n"
    		"1. \"pubkey\"         (string, required) Pubkey of to be certified\n"
    		"2. \"address\"        (string, required) Address of signer\n"
    		"3. \"oname\"          (string, required) Name of owner of public key\n"
    		"4. \"ogeo-addr\"      (string, required) Geographic address of owner of public key\n"
    		"5. \"ophone\"         (string, required) Phone number of owner of public key\n"
    		"6. \"oe-mail\"        (string, required) email address of owner of public key\n"
    		"7. \"ohttp\"          (string, required) http address of owner of public key\n"
    		"8. \"sname\"          (string, required) Name of signer\n"
    		"9. \"sgeo-addr\"      (string, required) Geographic address of signer\n"
    		"10.\"sphone\"         (string, required) Phone number of signer\n"
    		"11.\"semail\"         (string, required) email address of signer\n"
    		"12.\"shttp\"          (string, required) http address of signer\n"
    		"13.\"expire\"         (number, optional) Expiration time of certificate in number of blocks from current block\n"
            "\nResult: None\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_signrawtransaction", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"pr@acme.com\" \"www.acme.com\" \"Western Ratings\" \"1210 Main Street\" \"\" \"\" \"www.western-ratings.com\" 5000\n" )
            + HelpExampleRpc("eb_signrawtransaction", "\"39sdfd34341q5q45qdfaert2gfgrD301\" \"dvj4entdva4tqkdaadfv\" \"ACME Corp.\" \"100 Avenue Road\" \"519 435-1932\" \"pr@acme.com\" \"www.acme.com\" \"Western Ratings\" \"1210 Main Street\" \"\" \"\" \"www.western-ratings.com\" 5000\n" )
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

/******************************************************************************
eb_revokewotcertificate

    Revokes a WOT certificate

    Parameters:

    1) Public key to be revoked
    2) Public key of signer
    3) Reason for revocation

    Return: True if successful

    Side Effects

    - Broadcasts wot-certificate-revoked message to the network
    - Saves certificate revoked record to the wallet
******************************************************************************/

UniValue edcrevokewotcertificate(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"pubkey\" \"address\" ( \"reason\" )\n"
    		"\nRevokes a WOT certificate.\n"
            "\nArguments:\n"
			"1. \"pubkey\"    (string, required) Public key to be revoked\n"
			"2. \"address\"   (string, required) Address of signer\n"
			"3. \"reason\"    (string, optional) Reason for revocation\n"
            "\nResult: true or false\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_signrawtransaction", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
            + HelpExampleRpc("eb_signrawtransaction", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

/******************************************************************************
eb_wotchainexists

    Determines if a trust chain exists between two entities (indentified by 
    their public keys).

    Parameters:

    1) Public key at end of the chain
    2) Public key at the beginning of the chain
    3) Maximum length of the chain. If this value is specified, then only 
       chains whose length is less than or equal to this value will be 
       accepted.

    Returns:  

    Let P1 be a public key beginning of the chain. A public key P2 is a link 
    to P1 if a certificate that has not expired or been revoked exists 
    containing P1 that was signed by the private key corresponding to P2.

    Let the second parameter be P1 and the first parameter, Pn. If there exists 
    public keys P2, ..., Pn-1 such that P1 links to P2, P2 links to P3, ..., 
    Pn-1 links to Pn, then there exists a chain of length n-1 between P1 and Pn. 
    If the third parameter is not specified, or if it is greater than or equal 
    to n-1, then true is returned.  Otherwise, false it returned.

    Note that there may be more then one chain between P1 and Pn. All that is
    required is that one of them be short enough.

    Side Effects: None.
******************************************************************************/

UniValue edcwotchainexists(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "eb_requestwotcertificate \"epubkey\" \"bpubkey\" ( maxlen )\n"
			"\nDetermines if a trust chain exists between two entities (indentified by\n"
			"their public keys).\n"
            "\nArguments:\n"
			"1. \"epubkey\"    (string, required) Public key at the end of the chain\n"
			"2. \"bpubkey\"    (string, required) Public key at the beginning of the chain\n"
			"3. maxlen         (number, optional) Maximum length of the chain. Defaults to 2\n"
            "\nResult: true or false\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_wotchainexists", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\" 3")
            + HelpExampleRpc("eb_wotchainexists", "\"1234d20sdmDScedc2edscad\" \"0cmscadc9dcadsadvadvava\"")
        );

    UniValue result(UniValue::VOBJ);

    return result;
}

namespace
{

const CRPCCommand edcCommands[] =
{ //  category        name                        actor (function)           okSafeMode
  //  --------------- --------------------------- -----------------------    ----------
    { "equibit",      "eb_requestwotcertificate", &edcrequestwotcertificate, true },
    { "equibit",      "eb_getwotcertificate",     &edcgetwotcertificate,     true },
    { "equibit",      "eb_revokewotcertificate",  &edcrevokewotcertificate,  true },
    { "equibit",      "eb_wotchainexits",         &edcwotchainexists,        true },
};

}

void edcRegisterWoTRPCCommands(CEDCRPCTable & edcTableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        edcTableRPC.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}
