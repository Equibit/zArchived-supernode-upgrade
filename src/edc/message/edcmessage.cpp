// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcmessage.h"
#include "streams.h"
#include "edc/edcapp.h"
#include "key.h"
#include "edc/wallet/edcwallet.h"
#include "edc/edcmain.h"
#include <stdexcept>
#include <sstream>


////////////////////////////////////////////////////////////////////////////////
// The message tags
//

std::string CAcquisition::tag() const				{ return "Acquisition"; }
std::string CAsk::tag() const						{ return "Ask"; }
std::string CAssimilation::tag() const				{ return "Assimilation"; }

std::string CBankruptcy::tag() const				{ return "Bankruptcy"; }
std::string CBid::tag() const						{ return "Bid"; }
std::string CBonusIssue::tag() const				{ return "BonusIssue"; }
std::string CBonusRights::tag() const				{ return "BonusRights"; }
std::string CBuyBackProgram::tag() const			{ return "BuyBackProgram"; }

std::string CCashDividend::tag() const				{ return "CashDividend"; }
std::string CCashStockOption::tag() const			{ return "CashStockOption"; }
std::string CClassAction::tag() const 				{ return "ClassAction"; }
std::string CConversionOfConvertibleBonds::tag() const { return "ConversionOfConvertibleBonds"; }
std::string CCouponPayment::tag() const				{ return "CouponPayment"; }

std::string CDelisting::tag() const					{ return "Delisting"; }
std::string CDeMerger::tag() const					{ return "DeMerger"; }
std::string CDividendReinvestmentPlan::tag() const	{ return "DividendReinvestmentPlan"; }
std::string CDutchAuction::tag() const				{ return "DutchAuction"; }

std::string CEarlyRedemption::tag() const			{ return "EarlyRedemption"; }

std::string CFinalRedemption::tag() const			{ return "FinalRedemption"; }

std::string CGeneralAnnouncement::tag() const		{ return "GeneralAnnouncement"; }

std::string CInitialPublicOffering::tag() const		{ return "InitialPublicOffering"; }

std::string CLiquidation::tag() const				{ return "Liquidation"; }
std::string CLottery::tag() const					{ return "Lottery"; }

std::string CMandatoryExchange::tag() const			{ return "MandatoryExchange"; }
std::string CMerger::tag() const					{ return "Merger"; }
std::string CMergerWithElections::tag() const		{ return "MergerWithElections"; }

std::string CNameChange::tag() const				{ return "NameChange"; }

std::string COddLotTender::tag() const				{ return "OddLotTender"; }
std::string COptionalPut::tag() const				{ return "OptionalPut"; }
std::string COtherEvent::tag() const				{ return "OtherEvent"; }

std::string CPartialRedemption::tag() const			{ return "PartialRedemption"; }
std::string CParValueChange::tag() const			{ return "ParValueChange"; }
std::string CPoll::tag() const						{ return "Poll"; }
std::string CPrivate::tag() const					{ return "Private"; }

std::string CReturnOfCapital::tag() const			{ return "ReturnOfCapital"; } 
std::string CReverseStockSplit::tag() const			{ return "ReverseStockSplit"; }
std::string CRightsAuction::tag() const				{ return "RightsAuction"; }
std::string CRightsIssue::tag() const				{ return "RightsIssue"; }

std::string CSchemeofArrangement::tag() const		{ return "SchemeofArrangement"; }
std::string CScripDividend::tag() const				{ return "ScripDividend"; }
std::string CScripIssue::tag() const				{ return "ScripIssue"; }
std::string CSpinoff::tag() const					{ return "Spinoff"; }
std::string CSpinOffWithElections::tag() const		{ return "SpinOffWithElections"; }
std::string CStockDividend::tag() const				{ return "StockDividend"; }
std::string CStockSplit::tag() const				{ return "StockSplit"; }
std::string CSubscriptionOffer::tag() const			{ return "SubscriptionOffer"; }

std::string CTakeover::tag() const					{ return "Takeover"; }
std::string CTenderOffer::tag() const				{ return "TenderOffer"; }

std::string CVoluntaryExchange::tag() const			{ return "VoluntaryExchange"; }
std::string CVote::tag() const						{ return "Vote"; }

std::string CWarrantExercise::tag() const			{ return "WarrantExercise"; }
std::string CWarrantExpiry::tag() const				{ return "WarrantExpiry"; }
std::string CWarrantIssue::tag() const				{ return "WarrantIssue"; }

////////////////////////////////////////////////////////////////////////////////
// The message descriptions 
//

std::string CAcquisition ::desc() const
{
	return "A company adopting a growth strategy, can use several means in order to seize control of other companies.";
}
std::string CAsk::desc() const
{
	return "The price at which the owner of Equibit(s} is willing to sell the specified number of Equibits.";
}
std::string CAssimilation::desc() const
{
	return "Absorption of a new issue of stock into the parent security where the original shares did not fully rank pari passu with the parent shares.  After the event, the assimilated shares rank pari passu with the parent.  Also referred to as funging of shares.";
}

std::string CBankruptcy::desc() const
{
	return "The company announces bankruptcy protection and the legal proceedings start in which it will be decided what pay-outs will be paid to stakeholders.";
}
std::string CBid::desc() const
{
	return "The price at which the market participant is will to pay for the specified number of Equibits.";
}
std::string CBonusIssue::desc() const
{
	return "Shareholders are awarded additional securities (shares, rights or warrants} free of payment.The nominal value of shares does not change.";
}
std::string CBonusRights::desc() const
{
	return "Distribution of rights which provide existing shareholders the privilege to subscribe to additional shares at a discounted rate. This corporate action has similar features to a bonus and rights issue.";
}
std::string CBuyBackProgram::desc() const
{
	return "Offer by the issuing company to existing shareholders to repurchase the company’s own shares or other securities convertible into shares.  This results in a reduction in the number of outstanding shares.";
}

std::string CCashDividend::desc() const
{
	return "The company pays out a cash amount to distribute its profits to shareholders.";
}
std::string CCashStockOption::desc() const
{
	return "Shareholders are offered the choice to receive the dividend in cash or in additional new shares of the company (at a discount to market}. Reinvesting often carries a tax shield.";
}
std::string CClassAction::desc() const
{
	return "A lawsuit is being made against the company (usually by a large group of shareholders or by a representative person or organisation} that may result in a payment to the shareholders.";
}
std::string CConversionOfConvertibleBonds::desc() const
{
	return "Convertible bonds are being converted in the underlying shares.";
}
std::string CCouponPayment::desc() const
{
	return "The issuer of the bond pays interst according to the terms and conditions of the bond, ie interest rate and intervals of payment.";
}

std::string CDelisting::desc() const
{
	return "The company announces that it securities will no longer be listed on a stock exchange and that they will be booked out.";
}
std::string CDeMerger::desc() const
{
	return "One company de-merges itself into 2 or more companies. The shares of the old company are booked out and the shares of the new companies will be booked in according to a set ratio.";
}
std::string CDividendReinvestmentPlan::desc() const
{
	return "Similar to cash stock option. In this case however, the company first pays the cash dividend after which shareholders are offered the possibility to reinvest the cash dividend in new shares.";
}
std::string CDutchAuction::desc() const
{
	return "A Dutch Auction Offer specifies a price range within which a fixed number of shares will ultimately be purchased. Shareholders are asked to submit instructions as to what price they are willing to sell. Once all instructions have been counted, the shares of the shareholders who voted to sell at the lowest prices will be bought untill either the fixed number of shares is reached or the upper limit of the price range is reached.";
}
	
std::string CEarlyRedemption::desc() const
{
	return "The issuer of the bond repays the nominal prior to the maturity date of the bond, normally with accrued interest.";
}
	
std::string CFinalRedemption::desc() const
{
	return "The issuer of the bond repays the nominal of the bond, normally with accrued interest.";
}

std::string CGeneralAnnouncement::desc() const
{
	return "An event used by the company to notify its shareholders of any events that take place. This event type is used to communicate several types of information to the shareholders.";
}

std::string CInitialPublicOffering::desc() const
{
	return "This is the first corporate actions event in the history of any company. The first time that a company gets listed on a stock exchange is regarded as an event in itself. Underwriters will try to get as many buyers for the newly listed shares for a price as high as possible. Any shares they can not sell, will be bought by the underwriters.";
}

std::string CLiquidation::desc() const
{
	return "Liquidation proceedings consist of a distribution of cash and/or assets. Debt may be paid in order of priority based on preferred claims to assets specified by the security e.g. ordinary shares versus preferred shares.";
}

std::string CLottery::desc() const
{
	return "The issuer redeems selected holdings before the maturity date of the bond (early redemption}.";
}
std::string CMandatoryExchange::desc() const
{
	return "Conversion of securities (generally convertible bonds or preferred shares} into a set number of other forms of securities (usually common shares).";
}
std::string CMerger::desc() const
{
	return "Merger of 2 or more companies into one new company. The shares of the old companies are consequently exchanged into shares in the new company according to a set ratio.";
}
std::string CMergerWithElections::desc() const
{
	return "Merger of 2 or more companies into one new company. The shares of the old companies are consequently exchanged into shares in the new company according to a set ratio. Shareholders of both companies are offered choices regarding the securities they receive";
}
std::string CNameChange::desc() const
{
	return "Name changes are normally proposed and approved at the Company’s General meeting.  This has no effect on the capital and shareholder’s of the company.";
}
std::string COddLotTender::desc() const
{
	return "In case shares are tradeable in so called board lots of for example 100 shares only and a shareholder has an amount of shares that is not a multiple of the board lot, then this additional quantity is called odd lot. An odd lot tender is an offer to shareholders with odd lots to sell the shares in the odd lot at a given price. So for example, if the board lot is 100 and a shareholder holds 150 shares, an odd lot tender will give the shareholder to dispose of 50 shares at a given price. The board lot of 100 will still be tradable as normal.";
}
std::string COptionalPut::desc() const
{
	return "An event in which the holder of the put options has the option to exercise the put option in order to sell the underlying security at a given price.";
}
std::string COtherEvent::desc() const
{
	return "Any event that does not fit any of the other descriptions.";
}
std::string CPartialRedemption::desc() const
{
	return "The issuer of the bond repays part of the nominal prior to maturity, normally with accrued interest.";
}
std::string CParValueChange::desc() const
{
	return "Similar to stock splits where the share nominal value is changed which normally results in a change in the number of shares held.";
}
std::string CPrivate::desc() const
{
	return "A private message";
}
std::string CReturnOfCapital::desc() const
{
	return "A cash amount will be paid to investors in combination with a nominal value change of the shares.";
}
std::string CReverseStockSplit::desc() const
{
	return "The number of outstanding shares of the company gets reduced by an ‘X’ number while the nominal value of the shares increases by ‘X’. For example a ‘BMW' 1 for 2 reverse stock split, where the BMW shares’ nominal value increases from EUR 0.50 to EUR 1.00. The total value of the outstanding shares remains the same.";
}
std::string CRightsAuction::desc() const
{
	return "Rights to buy new shares are being auctioned - shareholders who submit the highest prices at which they are willing to buy new shares will get the new shares.";
}
std::string CRightsIssue::desc() const
{
	return "Rights are issued to entitled shareholders of the underlying stock.  They allow the rights holder to subscribe to additional shares of either the same stock or another stock or convertible bond, at the predetermined rate/ratio and price (usually at a discount to the market rate}. Rights are normally tradable and can be sold/bought in the market, exercised or lapsed.";
}
std::string CSchemeofArrangement::desc() const
{
	return "Occurs when a parent company takes over its subsidiaries and distributes proceeds to its shareholders.";
}
std::string CScripDividend::desc() const
{
	return "The UK version of an optional dividend.  No stock dividends / coupons are issued but the shareholder can elect to receive either cash or new shares based on the ratio or by the net dividend divided by the re-investment price.  The default is always cash.";
}
std::string CScripIssue::desc() const
{
	return "Shareholders are awarded additional securities (shares, rights or warrants} free of payment.  The nominal value of shares does not change";
}
std::string CSpinoff::desc() const
{
	return "A distribution of subsidiary stock to the shareholders of the parent corporation without having cost to the shareholder of the parent issue.";
}
std::string CSpinOffWithElections::desc() const
{
	return "A distribution of subsidiary stock to the shareholders of the parent corporation without having cost to the shareholder of the parent issue whereby the shareholders are offered choices regarding the resultant stock.";
}
std::string CStockDividend::desc() const
{
	return "Almost identical to bonus issues where additional shares in either the same or different stock is issued to shareholders of the underlying stock. ";
}

std::string CStockSplit::desc() const
{
	return "A stock split is a division of the company shares into ‘X’ number of new shares with a nominal value of ‘1/X’ of the original share.  For example a ‘BMW’ 2 for 1 stock split, where a BMW share par value decreases to EUR 0.50 from EUR 1.00, whilst the number of share doubles. The total value of the outstanding shares remains the same.";
}
std::string CSubscriptionOffer::desc() const
{
	return "Offer to existing shareholders to subscribe to new stock or convertible bonds";
}

std::string CTakeover::desc() const
{
	return "One company taking control over another company (usually by acquiring the majority of outstanding share voting rights.";
}
std::string CTenderOffer::desc() const
{
	return "Offer from Company A to shareholders of Company B to tender their shares to company A at a given price. The given price can be payable in cash only, stock in Company B only or a combination of cash and stock.";
}
std::string CVoluntaryExchange::desc() const
{
	return "Offer to exchange shares of security A into cash or into Security B.";
}
std::string CVote::desc() const
{
	return "Share holder response to company referendum.";
}
std::string CPoll::desc() const
{
	return "Every publicly traded company has an annual general meeting where management presents several decisions that need shareholder approval. The approval is given by means of voting for or against each decision. Shareholders may attend the meeting in person or vote by proxy - electronically or by mail via their brokers and custodian.";
}
std::string CWarrantExercise::desc() const
{
	return "An event in which the holder of the warrants has the option to exercise the warrant in accordance with the terms and conditions of the warrant.";
}
std::string CWarrantExpiry::desc() const
{
	return "An event that notifies the holder of the warrant that the warrant is about to expire and the holder of the warrant is given the option to exercise the warrant.";
}
std::string CWarrantIssue::desc() const
{
	return "Per share an amount of warrants is issued according to a specific ratio. The warrant can entitle to sell or buy the underlying security at a given price within a given timeframe.";
}

///////////////////////////////////////////////////////////////////////////////

namespace
{
CBroadcast * broadcastObj( const std::string & tag )
{
	if( tag[0] == 'A' )
	{
		if( tag == "Acquisition" )				return new CAcquisition();
		else if( tag == "Ask" )					return new CAsk();
		else if( tag == "Assimilation" )		return new CAssimilation();
	}
	else if( tag[0] == 'B' )
	{
		if( tag == "Bankruptcy" )				return new CBankruptcy();
		else if( tag == "Bid" )					return new CBid();
		else if( tag == "BonusIssue" )			return new CBonusIssue();
		else if( tag == "BonusRights" )			return new CBonusRights();
		else if( tag == "BuyBackProgram" )		return new CBuyBackProgram();
	}
	else if( tag[0] == 'C' )
	{
		if( tag == "CashDividend" )				return new CCashDividend();
		else if( tag == "CashStockOption" )		return new CCashStockOption();
		else if( tag == "ClassAction" ) 		return new CClassAction();
		else if( tag == "ConversionOfConvertibleBonds" )	return new CConversionOfConvertibleBonds();
		else if( tag == "CouponPayment" )		return new CCouponPayment();
	}
	else if( tag[0] == 'D' )
	{
		if( tag == "Delisting" )				return new CDelisting();
		else if( tag == "DeMerger" )			return new CDeMerger();
		else if( tag == "DividendReinvestmentPlan" )	return new CDividendReinvestmentPlan();
		else if( tag == "DutchAuction" )		return new CDutchAuction();
	}
	else if( tag[0] == 'E' )
	{
		if( tag == "EarlyRedemption" )			return new CEarlyRedemption();
	}
	else if( tag[0] == 'F' )
	{
		if( tag == "FinalRedemption" )			return new CFinalRedemption();
	}
	else if( tag[0] == 'G' )
	{
		if( tag == "GeneralAnnouncement" )		return new CGeneralAnnouncement();
	}
	else if( tag[0] == 'I' )
	{
		if( tag == "InitialPublicOffering" )	return new CInitialPublicOffering();
	}
	else if( tag[0] == 'L' )
	{
		if( tag == "Liquidation" )				return new CLiquidation();
		else if( tag == "Lottery" )				return new CLottery();
	}
	else if( tag[0] == 'M' )
	{
		if( tag == "MandatoryExchange" )		return new CMandatoryExchange();
		else if( tag == "Merger" )				return new CMerger();
		else if( tag == "MergerWithElections" )	return new CMergerWithElections();
	}
	else if( tag[0] == 'N' )
	{
		if( tag == "NameChange" )				return new CNameChange();
	}
	else if( tag[0] == 'O' )
	{
		if( tag == "OddLotTender" )				return new COddLotTender();
		else if( tag == "OptionalPut" )			return new COptionalPut();
		else if( tag == "OtherEvent" )			return new COtherEvent();
	}
	else if( tag[0] == 'P' )
	{
		if( tag == "PartialRedemption" )		return new CPartialRedemption();
		else if( tag == "ParValueChange" )		return new CParValueChange();
	}
	else if( tag[0] == 'R' )
	{
		if( tag == "ReturnOfCapital" )			return new CReturnOfCapital();
		else if( tag == "ReverseStockSplit" )	return new CReverseStockSplit();
		else if( tag == "RightsAuction" )		return new CRightsAuction();
		else if( tag == "RightsIssue" )			return new CRightsIssue();
	}
	else if( tag[0] == 'S' )
	{
		if( tag == "SchemeofArrangement" )		return new CSchemeofArrangement();
		else if( tag == "ScripDividend" )		return new CScripDividend();
		else if( tag == "ScripIssue" )			return new CScripIssue();
		else if( tag == "Spinoff" )				return new CSpinoff();
		else if( tag == "SpinOffWithElections" )return new CSpinOffWithElections();
		else if( tag == "StockDividend" )		return new CStockDividend();
		else if( tag == "StockSplit" )			return new CStockSplit();
		else if( tag == "SubscriptionOffer" )	return new CSubscriptionOffer();
	}
	else if( tag[0] == 'T' )
	{
		if( tag == "Takeover" )					return new CTakeover();
		else if( tag == "TenderOffer" )			return new CTenderOffer();
	}
	else if( tag[0] == 'V' )
	{
		if( tag == "VoluntaryExchange" )		return new CVoluntaryExchange();
	}
	else if( tag[0] == 'W' )
	{
		if( tag == "WarrantExercise" )			return new CWarrantExercise();
		else if( tag == "WarrantExpiry" )		return new CWarrantExpiry();
		else if( tag == "WarrantIssue" )		return new CWarrantIssue();
	}
	return NULL;
}

void signMessage(
			  const CKeyID & keyID,    // IN
			const timespec & ts, 	   // IN
					uint64_t nonce,	   // IN
		 const std::string & type,     // IN
		 const std::string & assetId,  // IN
		 const std::string & message,  // IN
std::vector<unsigned char> & signature // OUT
    )
{
    EDCapp & theApp = EDCapp::singleton();

    CKey key;
    if (!theApp.walletMain()->GetKey(keyID, key))
        throw std::runtime_error("Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << edcstrMessageMagic
	   << ts.tv_sec
	   << ts.tv_nsec
	   << nonce
       << type
       << assetId
       << message;

    if (!key.SignCompact(ss.GetHash(), signature ))
        throw std::runtime_error("Sign failed");
}

bool verifyMessage(
					const CKeyID & keyID,    // IN
				  const timespec & ts, 	   	 // IN
						  uint64_t nonce,	 // IN
			   const std::string & type,     // IN
			   const std::string & assetId,  // IN
			   const std::string & message,  // IN
const std::vector<unsigned char> & signature // IN
    )
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << edcstrMessageMagic
	   << ts.tv_sec
	   << ts.tv_nsec
	   << nonce
       << type
       << assetId
       << message;

	CPubKey	pubkey;
    return pubkey.RecoverCompact(ss.GetHash(), signature );
}

}

CUserMessage::CUserMessage():nonce_(0)
{
	clock_gettime( CLOCK_REALTIME, &timestamp_ );
}

CUserMessage * CUserMessage::create( const std::string & tag, CDataStream & str )
{
	if( CBroadcast * result = broadcastObj( tag ))
	{
		try
		{
			str >> *result;
		}
		catch( ... )
		{
			delete result;
			throw;
		}

		return result;
	}

	CPeerToPeer * result = NULL;
	if( tag == "Vote" )
		result = new CVote();
	else if( tag == "Private" )
		result = new CPrivate();

	if(result)
	{
		try
		{
			str >> *result;
		}
		catch( ... )
		{
			delete result;
			throw;
		}

		return result;
	}
	else if( tag == "Poll" )
	{
		CMulticast * result = new CPoll();

		try
		{
			str >> *result;
		}
		catch( ... )
		{
			delete result;
			throw;
		}

		return result;
	}

	throw std::runtime_error( "CUserMessage::create(): unsupported message tag " + tag );
}

void CUserMessage::proofOfWork()
{
	arith_uint256	target;
	bool	neg;
	bool	over;

	// The first parameter sets the target value. The value is 256 bits or 
	// 128-nibbles long, where each nibble is 4-bits wide. A digit corresponds to 
	// a nibble of the number. The first two digits of the first parameter determine 
	// the number of leading 0s (or leading nibbles) in the value. The next 6 digits
	// are the leading digits of the target. The remaining digits are all 0s.
	//
	// The number of leading digits (where each digit corresponds to 4 bits) is:
	//
	// 20	0
	// 1F	2
	// 1E	4
	// 1D	6
	//
	// and so on.
	//
	// So, for example, 0x1D3FFFFF corresponds to 0000003FFFFF00000...0000.
	//
	// The smaller the target, the longer the search.
	//
	target.SetCompact( 0x1E2FFFFF, &neg, &over );

	while(true)
	{
		uint256 value = GetHash();
		
		arith_uint256	v256 = UintToArith256( value );

#if TRACE_MSG_POW
if(nonce_ % 1000 == 0 )
printf( "message POW: %lu:value=%s target=%s\n", nonce_, v256.ToString().c_str(), target.ToString().c_str() );
#endif
		if( v256 < target )
			break;
		++nonce_;
	}
}

CPeerToPeer * CPeerToPeer::create(
			   const std::string & type, 
         			const CKeyID & sender, 
		 			const CKeyID & receiver, 
			   const std::string & data )
{
	CPeerToPeer * ans;

	if( type == "Private" )
	{
		ans = new CPrivate();
	}
	else if( type == "Vote" )
	{
		ans = new CVote();
	}
	else
	{
		std::string msg = "Invalid peer-to-peer message type:";
		msg += type;
		throw std::runtime_error( msg );
	}

	ans->proofOfWork();

	ans->senderAddr_ = sender;
	ans->receiverAddr_ = receiver;
	ans->data_ = data;

	signMessage(sender,
				ans->timestamp_,
				ans->nonce_,
		 		type,
		 		receiver.ToString(),
		 		data,
				ans->signature_ );

	return ans;
}

CMulticast * CMulticast::create(
			   const std::string & type, 
			        const CKeyID & sender, 
			   const std::string & assetId, 
	   		   const std::string & data )
{
	CMulticast * ans;

	if( type == "Poll" )
	{
		ans = new CPoll();
	}
	else
	{
		std::string msg = "Invalid multicast message type:";
		msg += type;
		throw std::runtime_error( msg );
	}

	ans->proofOfWork();

	ans->senderAddr_ = sender;
	ans->assetId_ = assetId;
	ans->data_ = data;

	signMessage(sender,
				ans->timestamp_,
				ans->nonce_,
		 		type,
		 		assetId,
		 		data,
				ans->signature_ );
	return ans;
}

CBroadcast * CBroadcast::create(
			   const std::string & type, 
	     	        const CKeyID & sender, 
			   const std::string & assetId, 
			   const std::string & data )
{
	CBroadcast * ans = broadcastObj( type );

	if(!ans)
	{
		std::string msg = "Invalid broadcast message type:";
		msg += type;
		throw std::runtime_error( msg );
	}

	ans->proofOfWork();

	ans->senderAddr_ = sender;
	ans->assetId_ = assetId;
	ans->data_ = data;

	signMessage(sender,
				ans->timestamp_,
				ans->nonce_,
		 		type,
		 		assetId,
		 		data,
				ans->signature_ );
	return ans;
}

///////////////////////////////////////////////////////////////////////////

std::string	CUserMessage::ToString() const
{
	std::stringstream out;

	out << "sender=" << senderAddr_.ToString()
		<< " timestamp=" << timestamp_.tv_sec << ":" << timestamp_.tv_nsec
		<< " nonce=" << nonce_
		<< " data=[" << data_ << "]"
		<< " signature=" << HexStr(signature_);

	return out.str();
}

std::string	CPeerToPeer::ToString() const
{
	std::string ans = tag();
	ans += ":";
	ans += CUserMessage::ToString();

	ans += " receiver=";
	ans += receiverAddr_.ToString();

	return ans;
}

std::string	CMulticast::ToString() const
{
	std::string ans = tag();
	ans += ":";
	ans += CUserMessage::ToString();

	ans += " asset=";
	ans += assetId_;

	return ans;
}

std::string	CBroadcast::ToString() const
{
	std::string ans = tag();
	ans += ":";
	ans += CUserMessage::ToString();

	ans += " asset=";
	ans += assetId_;

	return ans;
}

///////////////////////////////////////////////////////////////////////////

std::string	CUserMessage::ToJSON() const
{
	std::stringstream out;

	time_t t = timestamp_.tv_sec;
	struct tm * ts = localtime(&t);

	const int BUF_SIZE = 64;
	char tbuf[BUF_SIZE];
	char buf[BUF_SIZE];

	strftime( tbuf, BUF_SIZE, "%Y-%m_%d %H:%M:%S", ts );
	snprintf( buf, BUF_SIZE, "%s.%06ld", tbuf, timestamp_.tv_nsec );

	out << ", \"hash\":\"" << GetHash().ToString() << "\""
		<< ", \"sender\":\"" << senderAddr_.ToString() << "\""
		<< ", \"timestamp\":\"" << buf << "\""
		<< ", \"nonce\":" << nonce_
		<< ", \"data\":\"" << data_ << "\""
		<< ", \"signature\":\"" << HexStr(signature_) << "\"";

	return out.str();
}

std::string	CPeerToPeer::ToJSON() const
{
	std::string ans = "{\"type\":\"";
	ans += tag();
	ans += "\"";
	ans += CUserMessage::ToJSON();

	ans += ", \"receiver\":\"";
	ans += receiverAddr_.ToString();
	ans += "\"}";

	return ans;
}

std::string	CMulticast::ToJSON() const
{
	std::string ans = "{\"type\":\"";
	ans += tag();
	ans += "\"";
	ans += CUserMessage::ToJSON();

	ans += ", \"asset\":\"";
	ans += assetId_;
	ans += "\"}";

	return ans;
}

std::string	CBroadcast::ToJSON() const
{
	std::string ans = "{\"type\":\"";
	ans += tag();
	ans += "\"";
	ans += CUserMessage::ToJSON();

	ans += ", \"asset\":\"";
	ans += assetId_;
	ans += "\"}";

	return ans;
}

///////////////////////////////////////////////////////////////////////////

bool CPeerToPeer::verify() const
{
	try
	{
		return verifyMessage(
			senderAddr_,
			timestamp_,
			nonce_,
		 	tag(),
		 	receiverAddr_.ToString(),
		 	data_,
			signature_ );
	}
	catch(...)
	{
		return false;
	}
}

bool CMulticast::verify() const
{
	try
	{
		return verifyMessage(
			senderAddr_,
			timestamp_,
			nonce_,
		 	tag(),
		 	assetId_,
		 	data_,
			signature_ );
	}
	catch(...)
	{
		return false;
	}
}

bool CBroadcast::verify() const
{
	try
	{
		return verifyMessage(
			senderAddr_,
			timestamp_,
			nonce_,
		 	tag(),
		 	assetId_,
		 	data_,
			signature_ );
	}
	catch(...)
	{
		return false;
	}
}

///////////////////////////////////////////////////////////////////////////

uint256 CMulticast::GetHash() const
{
	return SerializeHash(*this);
}

uint256 CBroadcast::GetHash() const
{
	return SerializeHash(*this);
}

uint256 CPeerToPeer::GetHash() const
{
	return SerializeHash(*this);
}

