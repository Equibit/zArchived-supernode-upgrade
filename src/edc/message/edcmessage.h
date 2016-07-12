// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>


// Message Format:
//
// Key							Value
// -----------------------------------
// Type:time-stamp:signature /  message
//
// Type			Message type
// time-stamp	When message was created
// signature	Message is signed by sender
//
// message		Data package
//

class CUserMessage
{
public:
	virtual std::string tag() const = 0;
	virtual std::string desc() const = 0;

};

// Message to a single recipient. Encrypted.
//
class PeerToPeer : public CUserMessage
{
public:

};

// Mesage to a specific collection of recipients
// Optionally encrypted.
//
class Multicast : public CUserMessage
{
public:

};

// Message to all addresses
// Not encrypted.
//
class Broadcast : public CUserMessage
{
public:

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

class Voting: public Multicast
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
