// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "primitives/transaction.h"
#include "amount.h"
#include "uint256.h"
#include "pubkey.h"
#include "script/script.h"


class CEDCTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CEDCTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /* If CEDCTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CEDCTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CEDCTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CEDCTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CEDCTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CEDCTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }

    friend bool operator==(const CEDCTxIn& a, const CEDCTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CEDCTxIn& a, const CEDCTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;

	std::string toJSON( const char * ) const;
};

enum Currency
{
	BTC
};

class CEDCTxOut
{
public:
	CAmount 	nValue;				// Num of equibits being transferred
	bool		forSale;			// Equibits are for sale
	uint256		receiptTxID;		// Related BTC Transaction ID (optional)
	CPubKey		ownerPubKey;		// Public Key of transaction owner
	uint160		ownerBitMsgAddr;	// Bitmessage address of transaction owner
	Currency	ownerPayCurr;		// Owner's payment currency
	uint160		ownerPayAddr;		// Owner's payment address
	CPubKey		issuerPubKey;		// Public Key of issuer
	uint160		issuerBitMsgAddr;	// Bitmessage address of issuer
	Currency	issuerPayCurr;		// Issuer's payment currency
	uint160		issuerPayAddr;		// Issuer's payment address
	CPubKey		proxyPubKey;		// Public Key of proxy agent (optional)
	uint160		proxyBitMsgAddr;	// Bitmessage address of proxy agent (optional)
	CScript		scriptPubKey;		// Script defining the conditions needed to
									// spend the output (ie. smart contract)

    CEDCTxOut():nValue(0), forSale(false), ownerPayCurr(BTC), issuerPayCurr(BTC)
    {
        SetNull();
    }

    CEDCTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(nValue);
		READWRITE(forSale);
		READWRITE(receiptTxID);
		READWRITE(ownerPubKey);
		READWRITE(ownerBitMsgAddr);
		READWRITE(ownerPayAddr);
		READWRITE(issuerPubKey);
		READWRITE(issuerBitMsgAddr);
		READWRITE(issuerPayAddr);
		READWRITE(proxyPubKey);
		READWRITE(proxyBitMsgAddr);
		READWRITE(*(CScriptBase*)(&scriptPubKey));

		if(ser_action.ForRead())
		{
			int curr;
			READWRITE(curr);
			ownerPayCurr = static_cast<Currency>(curr);
			READWRITE(curr);
			issuerPayCurr = static_cast<Currency>(curr);
		}
		else
		{
			int curr = ownerPayCurr;
			READWRITE(curr);
			curr = issuerPayCurr;
			READWRITE(curr);
		}
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const;

    CAmount GetDustThreshold(const CFeeRate &minRelayTxFee) const
    {
        // "Dust" is defined in terms of CEDCTransaction::minRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
        // A typical spendable txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend:
        // so dust is a spendable txout less than
        // 546*minRelayTxFee/1000 (in satoshis)
        if (scriptPubKey.IsUnspendable())
            return 0;

        size_t nSize = GetSerializeSize(SER_DISK,0)+148u;
        return 3*minRelayTxFee.GetFee(nSize);
    }

    bool IsDust(const CFeeRate &minRelayTxFee) const
    {
        return (nValue < GetDustThreshold(minRelayTxFee));
    }

    friend bool operator==(const CEDCTxOut& a, const CEDCTxOut& b)
    {
        return a.nValue  == b.nValue
			&& a.forSale == b.forSale
			&& a.receiptTxID == b.receiptTxID
			&& a.ownerPubKey == b.ownerPubKey
			&& a.ownerBitMsgAddr == b.ownerBitMsgAddr
			&& a.ownerPayCurr == b.ownerPayCurr
			&& a.ownerPayAddr == b.ownerPayAddr
			&& a.issuerPubKey == b.issuerPubKey
			&& a.issuerBitMsgAddr == b.issuerBitMsgAddr
			&& a.issuerPayCurr == b.issuerPayCurr
			&& a.issuerPayAddr == b.issuerPayAddr
			&& a.proxyPubKey == b.proxyPubKey
			&& a.proxyBitMsgAddr == b.proxyBitMsgAddr
            && a.scriptPubKey == b.scriptPubKey;
		;
    }

    friend bool operator!=(const CEDCTxOut& a, const CEDCTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;

	std::string toJSON( const char * ) const;
};

struct CEDCMutableTransaction;

class CEDCTransaction
{
private:
    /** Memory only. */
	const uint256 hash;
	void UpdateHash() const;

public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION=1;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION=2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CEDCTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const int32_t nVersion;
    const std::vector<CEDCTxIn> vin;
    const std::vector<CEDCTxOut> vout;
    const uint32_t nLockTime;

	/** Construct a CEDCTransaction that qualifies as IsNull() */
	CEDCTransaction();

	/** Convert a CEDCMutableTransaction into a CEDCTransaction. */
	CEDCTransaction(const CEDCMutableTransaction &tx);

	CEDCTransaction& operator=(const CEDCTransaction& tx);

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(*const_cast<int32_t*>(&this->nVersion));
		nVersion = this->nVersion;
		READWRITE(*const_cast<std::vector<CEDCTxIn>*>(&vin));
		READWRITE(*const_cast<std::vector<CEDCTxOut>*>(&vout));
		READWRITE(*const_cast<uint32_t*>(&nLockTime));
		if (ser_action.ForRead())
			UpdateHash();
	}

	bool IsNull() const 
	{
		return vin.empty() && vout.empty();
	}

	const uint256& GetHash() const 
	{
		return hash;
	}

	// Return sum of txouts.
	CAmount GetValueOut() const;
	// GetValueIn() is a method on CCoinsViewCache, because
	// inputs must be known to compute value in.

	// Compute priority, given priority of inputs and (optionally) tx size
	double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

	// Compute modified tx size for priority calculation (optionally given tx size)
	unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

	bool IsCoinBase() const
	{
		return (vin.size() == 1 && vin[0].prevout.IsNull());
	}

	friend bool operator==(const CEDCTransaction& a, const CEDCTransaction& b)
	{
		return a.hash == b.hash;
	}

	friend bool operator!=(const CEDCTransaction& a, const CEDCTransaction& b)
	{
		return a.hash != b.hash;
	}

	std::string ToString() const;

	std::string toJSON( const char * ) const;
};

/** A mutable version of CEDCTransaction. */
struct CEDCMutableTransaction
{
	int32_t nVersion;
	std::vector<CEDCTxIn> vin;
	std::vector<CEDCTxOut> vout;
	uint32_t nLockTime;

	CEDCMutableTransaction();
	CEDCMutableTransaction(const CEDCTransaction& tx);

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(this->nVersion);
		nVersion = this->nVersion;
		READWRITE(vin);
		READWRITE(vout);
		READWRITE(nLockTime);
	}

	/** Compute the hash of this CEDCMutableTransaction. This is computed on the
	 * fly, as opposed to GetHash() in CEDCTransaction, which uses a cached result.
	 */
	uint256 GetHash() const;
};

