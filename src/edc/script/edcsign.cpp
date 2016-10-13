// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/script/edcsign.h"

#include "key.h"
#include "edc/wallet/edcwallet.h"
#include "edc/policy/edcpolicy.h"
#include "edc/primitives/edctransaction.h"
#include "script/standard.h"
#include "uint256.h"
#ifdef USE_HSM
#include "edc/edcapp.h"
#include "edc/edcparams.h"
#include "Thales/interface.h"
#include <secp256k1.h>

namespace
{
secp256k1_context	* secp256k1_context_verify;

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

Verifier	verifier;

}

#endif

#include <boost/foreach.hpp>

using namespace std;

typedef std::vector<unsigned char> valtype;

EDCTransactionSignatureCreator::EDCTransactionSignatureCreator(
		  const CKeyStore * keystoreIn, 
	const CEDCTransaction * txToIn, 
			   unsigned int nInIn, 
			const CAmount & amountIn, 
						int nHashTypeIn) : 
	BaseSignatureCreator(keystoreIn), 
	txTo(txToIn), 
	nIn(nInIn), 
	nHashType(nHashTypeIn), 
	amount(amountIn), 
	checker(txTo, nIn, amountIn) 
{}

bool EDCTransactionSignatureCreator::CreateSig(
	std::vector<unsigned char> & vchSig, 
				  const CKeyID & address, 
				 const CScript & scriptCode) const
{
    CKey key;
    if (!keystore->GetKey(address, key))
	{
#ifdef USE_HSM
		EDCparams & params = EDCparams::singleton();

		if( params.usehsm )
		{
			const CEDCWallet * wallet = dynamic_cast<const CEDCWallet *>(keystore);

			if( wallet )
			{
				std::string hsmID;
				if( wallet && wallet->GetHSMKey(address, hsmID))
				{
					EDCapp & theApp = EDCapp::singleton();
	
   			 		uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, SIGVERSION_BASE);
   			 		if (!NFast::sign( *theApp.nfHardServer(), *theApp.nfModule(), 
					hsmID, hash.begin(), 256, vchSig))
   	     				return false;
	
					secp256k1_ecdsa_signature sig;
					memcpy( sig.data, vchSig.data(), sizeof(sig.data));

					secp256k1_ecdsa_signature_normalize( secp256k1_context_verify, &sig, &sig );
	
					vchSig.resize(72);
   			 		size_t nSigLen = 72;
	
			    	secp256k1_ecdsa_signature_serialize_der( secp256k1_context_verify, 
						(unsigned char*)&vchSig[0], &nSigLen, &sig);
				    vchSig.resize(nSigLen);
   		 			vchSig.push_back((unsigned char)nHashType);
	
					return true;
				}
			}
		}
#endif
        return false;
	}

    uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, SIGVERSION_BASE);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    return true;
}

namespace
{

bool edcSign1(const CKeyID& address, const BaseSignatureCreator& creator, const CScript& scriptCode, CScript& scriptSigRet)
{
    vector<unsigned char> vchSig;
    if (!creator.CreateSig(vchSig, address, scriptCode))
        return false;
    scriptSigRet << vchSig;
    return true;
}

bool edcSignN(const vector<valtype>& multisigdata, const BaseSignatureCreator& creator, const CScript& scriptCode, CScript& scriptSigRet)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (edcSign1(keyID, creator, scriptCode, scriptSigRet))
            ++nSigned;
    }
    return nSigned==nRequired;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
bool edcSignStep(
	const BaseSignatureCreator & creator, 
				 const CScript & scriptPubKey,
    				   CScript & scriptSigRet, 
					txnouttype & whichTypeRet)
{
    scriptSigRet.clear();

    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return edcSign1(keyID, creator, scriptPubKey, scriptSigRet);
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!edcSign1(keyID, creator, scriptPubKey, scriptSigRet))
            return false;
        else
        {
            CPubKey vch;
#ifndef USE_HSM
            creator.KeyStore().GetPubKey(keyID, vch);
#else
			if(!creator.KeyStore().GetPubKey(keyID, vch))
			{
				const CEDCWallet * wallet = dynamic_cast<const CEDCWallet *>(&creator.KeyStore());
				if( wallet )
				{
					wallet->GetHSMPubKey(keyID, vch);
				}
			}
#endif
            scriptSigRet << ToByteVector(vch);
        }
        return true;
    case TX_SCRIPTHASH:
        return creator.KeyStore().GetCScript(uint160(vSolutions[0]), scriptSigRet);

    case TX_MULTISIG:
        scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
        return (edcSignN(vSolutions, creator, scriptPubKey, scriptSigRet));
    }
    return false;
}

}

bool edcProduceSignature(
	const BaseSignatureCreator & creator, 
				 const CScript & fromPubKey, 
					   CScript & scriptSig)
{
    txnouttype whichType;
    if (!edcSignStep(creator, fromPubKey, scriptSig, whichType))
        return false;

    if (whichType == TX_SCRIPTHASH)
    {
        // Solver returns the subscript that need to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        CScript subscript = scriptSig;

        txnouttype subType;
        bool fSolved =
            edcSignStep(creator, subscript, scriptSig, subType) && subType != TX_SCRIPTHASH;
        // Append serialized subscript whether or not it is completely signed:
        scriptSig << valtype(subscript.begin(), subscript.end());
        if (!fSolved) return false;
    }

    // Test solution
    return edcVerifyScript(scriptSig, fromPubKey, NULL, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
}

bool SignSignature(
		   const CKeyStore & keystore, 
	  		 const CScript & fromPubKey, 
	CEDCMutableTransaction & txTo, 
				unsigned int nIn, 
						 int nHashType)
{
    assert(nIn < txTo.vin.size());
    CEDCTxIn& txin = txTo.vin[nIn];

    CEDCTransaction txToConst(txTo);
    EDCTransactionSignatureCreator creator(&keystore, &txToConst, nIn, nHashType);

    return edcProduceSignature(creator, fromPubKey, txin.scriptSig);
}

bool SignSignature(
		   const CKeyStore & keystore, 
	 const CEDCTransaction & txFrom, 
	CEDCMutableTransaction & txTo, 
				unsigned int nIn, 
						 int nHashType)
{
    assert(nIn < txTo.vin.size());
    CEDCTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CEDCTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, nHashType);
}

static CScript PushAll(const vector<valtype>& values)
{
    CScript result;
    BOOST_FOREACH(const valtype& v, values)
        result << v;
    return result;
}

static CScript CombineMultisig(
				 const CScript & scriptPubKey, 
	const BaseSignatureChecker & checker,
         const vector<valtype> & vSolutions,
         const vector<valtype> & sigs1, 
		 const vector<valtype> & sigs2)
{
    // Combine all the signatures we've got:
    set<valtype> allsigs;
    BOOST_FOREACH(const valtype& v, sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    BOOST_FOREACH(const valtype& v, sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size()-2;
    map<valtype, valtype> sigs;
    BOOST_FOREACH(const valtype& sig, allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (checker.CheckSig(sig, pubkey, scriptPubKey, SIGVERSION_BASE))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    CScript result; result << OP_0; // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
            result << sigs[vSolutions[i+1]];
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result << OP_0;

    return result;
}

static CScript edcCombineSignatures(
				 const CScript & scriptPubKey, 
	const BaseSignatureChecker & checker,
    			const txnouttype txType, 
		 const vector<valtype> & vSolutions,
    		   vector<valtype> & sigs1, 
			   vector<valtype> & sigs2)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.size() >= sigs2.size())
            return PushAll(sigs1);
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.empty() || sigs1[0].empty())
            return PushAll(sigs2);
        return PushAll(sigs1);
    case TX_SCRIPTHASH:
        if (sigs1.empty() || sigs1.back().empty())
            return PushAll(sigs2);
        else if (sigs2.empty() || sigs2.back().empty())
            return PushAll(sigs1);
        else
        {
            // Recur to combine:
            valtype spk = sigs1.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            vector<vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = edcCombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(scriptPubKey, checker, vSolutions, sigs1, sigs2);
    }

    return CScript();
}

CScript edcCombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                          const CScript& scriptSig1, const CScript& scriptSig2);

CScript edcCombineSignatures(
		    const CScript & scriptPubKey, 
	const CEDCTransaction & txTo, 
			   unsigned int nIn,
			const CAmount & amount,
            const CScript & scriptSig1, 
			const CScript & scriptSig2)
{
    EDCTransactionSignatureChecker checker(&txTo, nIn, amount);
    return edcCombineSignatures(scriptPubKey, checker, scriptSig1, scriptSig2);
}

CScript edcCombineSignatures(
				 const CScript & scriptPubKey, 
	const BaseSignatureChecker & checker,
                 const CScript & scriptSig1, 
				 const CScript & scriptSig2)
{
    txnouttype txType;
    vector<vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    vector<valtype> stack1;
    edcEvalScript(stack1, scriptSig1, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SIGVERSION_BASE);
    vector<valtype> stack2;
    edcEvalScript(stack2, scriptSig2, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SIGVERSION_BASE);

    return edcCombineSignatures(scriptPubKey, checker, txType, vSolutions, stack1, stack2);
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker : public BaseSignatureChecker
{
public:
    DummySignatureChecker() {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return true;
    }
};
const DummySignatureChecker dummyChecker;
}
