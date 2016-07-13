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

protected:
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
class PeerToPeer : public CUserMessage
{
public:
	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(*static_cast<CUserMessage *>(this));
		READWRITE(receiverAddr_);
	}

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
class Multicast : public CUserMessage
{
public:
	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(*static_cast<CUserMessage *>(this));
		READWRITE(securityId_);
	}

private:
	std::string securityId_;
};

// Message to all addresses
// Not encrypted.
//
// Message specific data:
//
// security-id:message-data
//
class Broadcast : public CUserMessage
{
public:
	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) 
	{
		READWRITE(*static_cast<CUserMessage *>(this));
		READWRITE(securityId_);
	}

private:
	std::string securityId_;
};

///////////////////////////////////////////////////////////

class Acquisition : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Ask : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Assimilation : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Bankruptcy : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Bid : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class BonusIssue : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class BonusRights : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class BuyBackProgram : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CashDividend : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CashStockOption : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ClassAction : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ConversionOfConvertibleBonds : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CouponPayment : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Delisting : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class DeMerger : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class DividendReinvestmentPlan : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class DutchAuction : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class EarlyRedemption : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class FinalRedemption : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class GeneralAnnouncement : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class InitialPublicOffering : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Liquidation : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Lottery : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class MandatoryExchange : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Merger : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class MergerWithElections : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class NameChange : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class OddLotTender : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class OptionalPut : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class OtherEvent : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class PartialRedemption : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ParValueChange : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Poll: public Multicast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Private: public PeerToPeer
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ReturnOfCapital : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ReverseStockSplit : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class RightsAuction : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class RightsIssue : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class SchemeofArrangement : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ScripDividend : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class ScripIssue : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Spinoff : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class SpinOffWithElections : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class StockDividend : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class StockSplit : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class SubscriptionOffer : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Takeover : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class TenderOffer : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class VoluntaryExchange : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class Vote: public PeerToPeer
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class WarrantExercise : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class WarrantExpiry : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};

class WarrantIssue : public Broadcast
{
public:
	virtual std::string tag() const;
	virtual std::string desc() const;
};
