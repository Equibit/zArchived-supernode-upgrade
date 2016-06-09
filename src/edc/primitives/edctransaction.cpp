// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/primitives/edctransaction.h"



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

// TODO: Review
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
/* TODO    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
*/
    return nTxSize;
}


CEDCMutableTransaction::CEDCMutableTransaction() : nVersion(CEDCTransaction::CURRENT_VERSION), nLockTime(0) {}
CEDCMutableTransaction::CEDCMutableTransaction(const CEDCTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {}

uint256 CEDCMutableTransaction::GetHash() const
{
    return SerializeHash(*this);
}

CEDCTxOut::CEDCTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
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
/* TODO
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
*/
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

std::string CEDCTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
/* TODO    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
*/
    str += ")";
    return str;
}

std::string CEDCTxOut::ToString() const
{
// TODO
//    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
	return "";
}

