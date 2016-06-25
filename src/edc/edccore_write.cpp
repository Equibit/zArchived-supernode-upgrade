// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edccore_io.h"

#include "edc/edcbase58.h"
#include "edc/primitives/edctransaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include <univalue.h>
#include "edcutil.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

using namespace std;

string edcFormatScript(const CScript& script)
{
    string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) 
	{
        CScript::const_iterator it2 = it;
        vector<unsigned char> vch;
        if (script.GetOp2(it, op, &vch)) 
		{
            if (op == OP_0) 
			{
                ret += "0 ";
                continue;
            } 
			else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) 
			{
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } 
			else if (op >= OP_NOP && op <= OP_NOP10) 
			{
                string str(GetOpName(op));
                if (str.substr(0, 3) == string("OP_")) 
				{
                    ret += str.substr(3, string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) 
			{
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            } 
			else 
			{
                ret += strprintf("0x%x ", HexStr(it2, it));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}

const map<unsigned char, string> mapSigHashTypes =
    boost::assign::map_list_of
    (static_cast<unsigned char>(SIGHASH_ALL), string("ALL"))
    (static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), string("ALL|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_NONE), string("NONE"))
    (static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), string("NONE|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_SINGLE), string("SINGLE"))
    (static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), string("SINGLE|ANYONECANPAY"))
    ;

string EncodeHexTx(const CEDCTransaction& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

void edcScriptPubKeyToUniv(
	const CScript & scriptPubKey,
         UniValue & out, 
			   bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.pushKV("asm", ScriptToAsmStr(scriptPubKey));
    if (fIncludeHex)
        out.pushKV("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) 
	{
        out.pushKV("type", GetTxnOutputType(type));
        return;
    }

    out.pushKV("reqSigs", nRequired);
    out.pushKV("type", GetTxnOutputType(type));

    UniValue a(UniValue::VARR);
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CEDCBitcoinAddress(addr).ToString());
    out.pushKV("addresses", a);
}

void TxToUniv(
	const CEDCTransaction & tx, 
			const uint256 & hashBlock, 
				 UniValue & entry)
{
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin(UniValue::VARR);
    BOOST_FOREACH(const CEDCTxIn& txin, tx.vin) 
	{
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else 
		{
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
            in.pushKV("scriptSig", o);
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) 
	{
        const CEDCTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        UniValue outValue(UniValue::VNUM, FormatMoney(txout.nValue));
        out.pushKV("value", outValue);
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        edcScriptPubKeyToUniv(txout.scriptPubKey, o, true);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    if (!hashBlock.IsNull())
        entry.pushKV("blockhash", hashBlock.GetHex());

    entry.pushKV("hex", EncodeHexTx(tx)); // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
}
