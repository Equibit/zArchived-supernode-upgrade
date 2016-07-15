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

	// If true, then the message is placed in a blockchain
	virtual bool chained() const = 0;

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
		READWRITE(data_);
	}

	void	proofOfWork();
	
	virtual std::string	ToString() const;

	static CUserMessage	* create( const std::string & type, CDataStream & );

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
								const std::string & data,
				 const std::vector<unsigned char> & signature );

	virtual std::string	ToString() const;

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

	virtual std::string	ToString() const;

	static CMulticast * create( const std::string & type, 
								     const CKeyID & sender, 
								const std::string & assetId, 
							    const std::string & data,
				 const std::vector<unsigned char> & signature );

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

	virtual std::string	ToString() const;

	static CBroadcast * create( const std::string & type, 
								     const CKeyID & sender, 
								const std::string & assetId, 
							    const std::string & data,
				 const std::vector<unsigned char> & signature );

private:
	std::string assetId_;
};

///////////////////////////////////////////////////////////

class CAcquisition : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CAsk : public CBroadcast
{
public:
	virtual bool chained() const { return false; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CAssimilation : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CBankruptcy : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CBid : public CBroadcast
{
public:
	virtual bool chained() const { return false; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CBonusIssue : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CBonusRights : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CBuyBackProgram : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CCashDividend : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CCashStockOption : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CClassAction : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CConversionOfConvertibleBonds : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CCouponPayment : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CDelisting : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CDeMerger : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CDividendReinvestmentPlan : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CDutchAuction : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CEarlyRedemption : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CFinalRedemption : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CGeneralAnnouncement : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CInitialPublicOffering : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CLiquidation : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CLottery : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CMandatoryExchange : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CMerger : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CMergerWithElections : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CNameChange : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class COddLotTender : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class COptionalPut : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class COtherEvent : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CPartialRedemption : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CParValueChange : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CPoll: public CMulticast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CPrivate: public CPeerToPeer
{
public:
	virtual bool chained() const { return false; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CReturnOfCapital : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CReverseStockSplit : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CRightsAuction : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CRightsIssue : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CSchemeofArrangement : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CScripDividend : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CScripIssue : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CSpinoff : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CSpinOffWithElections : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CStockDividend : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CStockSplit : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CSubscriptionOffer : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CTakeover : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CTenderOffer : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CVoluntaryExchange : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CVote: public CPeerToPeer
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CWarrantExercise : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CWarrantExpiry : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};

class CWarrantIssue : public CBroadcast
{
public:
	virtual bool chained() const { return true; }

	virtual std::string tag() const;
	virtual std::string desc() const;
};
