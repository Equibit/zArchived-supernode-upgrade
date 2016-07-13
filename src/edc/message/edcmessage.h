// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <time.h>
#include "pubkey.h"
#include "serialize.h"


class CDataStream;

// Abstract Base class of all User Message classes
//
// All user messages will have the format:
//
// USER:type:timestamp:sender-address:nonce:message-type-specific-data
//
class CUserMessage
{
public:
	CUserMessage() {}
	virtual ~CUserMessage() {}

	virtual std::string tag() const = 0;
	virtual std::string desc() const = 0;

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		if(ser_action.ForRead())
		{
    		time_t  sec;
		    long    nsec;

			READWRITE(sec);
			READWRITE(nsec);
	
			timestamp_.tv_sec = sec;
			timestamp_.tv_nsec= nsec;
		}
		else
		{
    		time_t  sec =  timestamp_.tv_sec;
		    long    nsec = timestamp_.tv_nsec;

			READWRITE(sec);
			READWRITE(nsec);
		}
   
		READWRITE(senderAddr_);
    	READWRITE(nonce_);
	}

	static CUserMessage	* create( const std::string & type, CDataStream & );

	void	proofOfWork();

protected:
	CUserMessage( const CKeyID & sender, const std::string & data );

	struct timespec	timestamp_;
	std::string		data_;
	CKeyID			senderAddr_;
	uint64_t		nonce_;
};

// Message to a single recipient. Encrypted.
//
// Message specific data:
//
// encrypted-message-data
//
class CPeerToPeer : public CUserMessage
{
public:
	CPeerToPeer() {}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(*static_cast<CUserMessage *>(this));
		READWRITE(receiverAddr_);
	}

	static CPeerToPeer * create(const std::string & type, 
								     const CKeyID & sender, 
								     const CKeyID & receiver, 
								const std::string & data );

protected:
	CPeerToPeer( const CKeyID & sender, const std::string & data );

private:
	CKeyID	receiverAddr_;
};

// Mesage to a specific collection of recipients
// Optionally encrypted.
//
// Message specific data:
//
// security-id:encrypted-message-data
//
class CMulticast : public CUserMessage
{
public:
	CMulticast() {}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(*static_cast<CUserMessage *>(this));
		READWRITE(assetId_);
	}

	static CMulticast * create( const std::string & type, 
								     const CKeyID & sender, 
								const std::string & assetId, 
							    const std::string & data );

protected:
	CMulticast( const CKeyID & sender, const std::string & data );

private:
	std::string assetId_;
};

// Message to all addresses
// Not encrypted.
//
// Message specific data:
//
// security-id:message-data
//
class CBroadcast : public CUserMessage
{
public:
	CBroadcast() {}

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(*static_cast<CUserMessage *>(this));
		READWRITE(assetId_);
	}

	static CBroadcast * create( const std::string & type, 
								     const CKeyID & sender, 
								const std::string & assetId, 
							    const std::string & data );

protected:
	CBroadcast( const CKeyID & sender, const std::string & data );

private:
	std::string assetId_;
};

///////////////////////////////////////////////////////////

class Acquisition : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Ask : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Assimilation : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Bankruptcy : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Bid : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class BonusIssue : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class BonusRights : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class BuyBackProgram : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CashDividend : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CashStockOption : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ClassAction : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ConversionOfConvertibleBonds : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CouponPayment : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Delisting : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class DeMerger : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class DividendReinvestmentPlan : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class DutchAuction : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class EarlyRedemption : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class FinalRedemption : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class GeneralAnnouncement : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class InitialPublicOffering : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Liquidation : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Lottery : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class MandatoryExchange : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Merger : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class MergerWithElections : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class NameChange : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class OddLotTender : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class OptionalPut : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class OtherEvent : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class PartialRedemption : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ParValueChange : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Poll: public CMulticast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Private: public CPeerToPeer
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ReturnOfCapital : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ReverseStockSplit : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class RightsAuction : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class RightsIssue : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class SchemeofArrangement : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ScripDividend : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ScripIssue : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Spinoff : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class SpinOffWithElections : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class StockDividend : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class StockSplit : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class SubscriptionOffer : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Takeover : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class TenderOffer : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class VoluntaryExchange : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Vote: public CPeerToPeer
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class WarrantExercise : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class WarrantExpiry : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class WarrantIssue : public CBroadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};
