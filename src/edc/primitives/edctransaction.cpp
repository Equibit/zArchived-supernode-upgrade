// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/primitives/edctransaction.h"
#include "utilstrencodings.h"
#include "tinyformat.h"
#include "edc/edcbase58.h"
#include <sstream>


void CEDCTransaction::UpdateHash() const
{
	*const_cast<uint256*>(&hash) = SerializeHash(*this);
}

CEDCTransaction::CEDCTransaction() : 
	nVersion(CEDCTransaction::CURRENT_VERSION), 
	vin(), 
	vout(), 
	nLockTime(0) 
{
}

CEDCTransaction::CEDCTransaction(const CEDCMutableTransaction &tx) : 
	nVersion(tx.nVersion), 
	vin(tx.vin), 
	vout(tx.vout), 
	nLockTime(tx.nLockTime) 
{
	UpdateHash();
}

CEDCTransaction& CEDCTransaction::operator=(const CEDCTransaction &tx) 
{
	*const_cast<int*>(&nVersion) = tx.nVersion;
	*const_cast<std::vector<CEDCTxIn>*>(&vin) = tx.vin;
	*const_cast<std::vector<CEDCTxOut>*>(&vout) = tx.vout;
	*const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
	*const_cast<uint256*>(&hash) = tx.hash;
	return *this;
}

CAmount CEDCTransaction::GetValueOut() const
{
	CAmount nValueOut = 0;
	for (std::vector<CEDCTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
	{
		nValueOut += it->nValue;
		if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
			throw std::runtime_error("CEDCTransaction::GetValueOut(): value out of range");
	}
	return nValueOut;
}

double CEDCTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
	nTxSize = CalculateModifiedSize(nTxSize);
	if (nTxSize == 0) 
		return 0.0;

	return dPriorityInputs / nTxSize;
}

unsigned int CEDCTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
	for (std::vector<CEDCTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }

    return nTxSize;
}


CEDCMutableTransaction::CEDCMutableTransaction() : nVersion(CEDCTransaction::CURRENT_VERSION), nLockTime(0) {}

CEDCMutableTransaction::CEDCMutableTransaction(const CEDCTransaction& tx) : 
	nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) 
{}

uint256 CEDCMutableTransaction::GetHash() const
{
    return SerializeHash(*this);
}

CEDCTxOut::CEDCTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn):
	nValue(nValueIn), 
	forSale(false), 
	ownerPayCurr(BTC), 
	issuerPayCurr(BTC),
	scriptPubKey(scriptPubKeyIn)
{
}

CEDCTxIn::CEDCTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CEDCTxIn::CEDCTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CEDCTransaction::ToString() const
{
    std::string str;

    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);

    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

std::string CEDCTransaction::toJSON( const char * margin ) const
{
	std::stringstream ans;

    ans << margin << "{\n";

	std::string innerMargin = margin;
	innerMargin += " ";

	time_t t = nLockTime;
	ans << innerMargin << "\"lockTime\":" << ctime( &t ) << ",\n";
	ans << innerMargin << "\"txIn\": [\n";

    auto ii =  vin.begin();
    auto ie =  vin.end();
	bool first = true;

	std::string inner2Margin = innerMargin + " ";
	while( ii != ie )
	{
		if(!first)
			ans << ", ";
		else
			first = false;

		ans << ii->toJSON( inner2Margin.c_str() );
		++ii;
	}
	ans << innerMargin << "],\n";

	ans << innerMargin << "\"txOut\": [\n";

    auto oi =  vout.begin();
    auto oe =  vout.end();
	first = true;

	while( oi != oe )
	{
		if(!first)
			ans << ", ";
		else
			first = false;

		ans << oi->toJSON( inner2Margin.c_str() );

		++oi;
	}
	ans << innerMargin << "]\n";

    ans << margin << "}\n";

	return ans.str();
}

std::string CEDCTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);

    str += ")";
    return str;
}

std::string CEDCTxIn::toJSON( const char * margin ) const
{
	std::stringstream ans;

	time_t t = prevout.n;
	time_t s = nSequence;
	ans << margin << "{\"prevout\":COutPoint(" << prevout.hash.ToString().substr(0,10) << "..," << ctime( &t ) << ")"
				  << ",\"scriptSig\":" << HexStr(scriptSig)
				  << ",\"sequence\":" << ctime( &s )
				  << "}";

	return ans.str();
}

namespace 
{
const char * ToString( Currency c )
{
	switch(c)
	{
	default:	return "ERROR:Unsupported currency";
	case BTC:	return "BTC";
	}
}
}

std::string CEDCTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, "
					"forSale=%s, "
					"receiptTxID=%s, "
					"ownerPubKey=%s, "
					"ownerBitMsgAddr=%s, "
					"ownerPayCurr=%s, "
					"ownerPayAddr=%s, "
					"issuerPubKey=%s, "
					"issuerBitMsgAddr=%s, "
					"issuerPayCurr=%s, "
					"issuerPayAddr=%s, "
					"proxyPubKey=%s, "
					"proxyBitMsgAddr=%s, "
					 "scriptPubKey=%s ...)", 
		nValue / COIN, nValue % COIN, 
		(forSale?"true":"false"),
		receiptTxID.ToString().c_str(),
		HexStr(ownerPubKey).c_str(),
		(ownerBitMsgAddr.IsNull() ? "" : CEDCBitcoinAddress(ownerBitMsgAddr).ToString().c_str()),
		::ToString(ownerPayCurr),
		(ownerPayAddr.IsNull() ? "" : CEDCBitcoinAddress(ownerPayAddr).ToString().c_str()),
		HexStr(issuerPubKey).c_str(),
		(issuerBitMsgAddr.IsNull() ? "" : CEDCBitcoinAddress(issuerBitMsgAddr).ToString().c_str()),
		::ToString(issuerPayCurr),
		(issuerPayAddr.IsNull() ? "" : CEDCBitcoinAddress(issuerPayAddr).ToString().c_str()),
		HexStr(proxyPubKey).c_str(),
		(proxyBitMsgAddr.IsNull() ? "" : CEDCBitcoinAddress(proxyBitMsgAddr).ToString().c_str()),
		HexStr(scriptPubKey).substr(0, 30));
}

std::string CEDCTxOut::toJSON( const char * margin ) const
{
	std::stringstream ans;

	ans << margin << "{\n" 
		<< margin << "\"value\":" << nValue << ",\n"
    	<< margin << "\"forSale\":" << forSale << ",\n"
    	<< margin << "\"receiptTxID\":" << receiptTxID.ToString() << ",\n"
    	<< margin << "\"ownerPubKey\":" << HexStr(ownerPubKey) << ",\n"
    	<< margin << "\"ownerBitMsgAddr\":" 
			<< (ownerBitMsgAddr.IsNull() ? "" : CEDCBitcoinAddress(ownerBitMsgAddr).ToString()) <<",\n"
    	<< margin << "\"currency\":" << ::ToString(ownerPayCurr) << ",\n"
    	<< margin << "\"ownerPayAddr\":" 
			<< (ownerPayAddr.IsNull() ? "" : CEDCBitcoinAddress(ownerPayAddr).ToString()) << ",\n"
    	<< margin << "\"issuerPubKey\":" << HexStr(issuerPubKey) << ",\n"
    	<< margin << "\"issuerBitMsgAddr\":"
			<< (issuerBitMsgAddr.IsNull() ? "" : CEDCBitcoinAddress(issuerBitMsgAddr).ToString()) << ",\n"
    	<< margin << "\"issuerPayCurr\":" << ::ToString(issuerPayCurr) << ",\n"
    	<< margin << "\"issuerPayAddr\":" 
			<< (issuerPayAddr.IsNull() ? "" : CEDCBitcoinAddress(issuerPayAddr).ToString()) << ",\n"
    	<< margin << "\"proxyPubKey\":" << HexStr(proxyPubKey) << ",\n"
    	<< margin << "\"proxyBitMsgAddr\":" 
			<< (proxyBitMsgAddr.IsNull() ? "" : CEDCBitcoinAddress(proxyBitMsgAddr).ToString()) << ",\n"
    	<< margin << "\"scriptPubKey\":" << HexStr(scriptPubKey) << ",\n"
		<< margin << "}";

	return ans.str();
}

