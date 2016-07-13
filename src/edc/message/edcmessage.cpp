// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcmessage.h"
#include "streams.h"
#include <stdexcept>


////////////////////////////////////////////////////////////////////////////////
// The message tags
//

std::string Acquisition::tag() const				{ return "Acquisition"; }
std::string Ask::tag() const						{ return "Ask"; }
std::string Assimilation::tag() const				{ return "Assimilation"; }

std::string Bankruptcy::tag() const					{ return "Bankruptcy"; }
std::string Bid::tag() const						{ return "Bid"; }
std::string BonusIssue::tag() const					{ return "BonusIssue"; }
std::string BonusRights::tag() const				{ return "BonusRights"; }
std::string BuyBackProgram::tag() const				{ return "BuyBackProgram"; }

std::string CashDividend::tag() const				{ return "CashDividend"; }
std::string CashStockOption::tag() const			{ return "CashStockOption"; }
std::string ClassAction::tag() const 				{ return "ClassAction"; }
std::string ConversionOfConvertibleBonds::tag() const { return "ConversionOfConvertibleBonds"; }
std::string CouponPayment::tag() const				{ return "CouponPayment"; }

std::string Delisting::tag() const					{ return "Delisting"; }
std::string DeMerger::tag() const					{ return "DeMerger"; }
std::string DividendReinvestmentPlan::tag() const	{ return "DividendReinvestmentPlan"; }
std::string DutchAuction::tag() const				{ return "DutchAuction"; }

std::string EarlyRedemption::tag() const			{ return "EarlyRedemption"; }

std::string FinalRedemption::tag() const			{ return "FinalRedemption"; }

std::string GeneralAnnouncement::tag() const		{ return "GeneralAnnouncement"; }

std::string InitialPublicOffering::tag() const		{ return "InitialPublicOffering"; }

std::string Liquidation::tag() const				{ return "Liquidation"; }
std::string Lottery::tag() const					{ return "Lottery"; }

std::string MandatoryExchange::tag() const			{ return "MandatoryExchange"; }
std::string Merger::tag() const						{ return "Merger"; }
std::string MergerWithElections::tag() const		{ return "MergerWithElections"; }

std::string NameChange::tag() const					{ return "NameChange"; }

std::string OddLotTender::tag() const				{ return "OddLotTender"; }
std::string OptionalPut::tag() const				{ return "OptionalPut"; }
std::string OtherEvent::tag() const					{ return "OtherEvent"; }

std::string PartialRedemption::tag() const			{ return "PartialRedemption"; }
std::string ParValueChange::tag() const				{ return "ParValueChange"; }
std::string Poll::tag() const						{ return "Poll"; }
std::string Private::tag() const					{ return "Private"; }

std::string ReturnOfCapital::tag() const			{ return "ReturnOfCapital"; } 
std::string ReverseStockSplit::tag() const			{ return "ReverseStockSplit"; }
std::string RightsAuction::tag() const				{ return "RightsAuction"; }
std::string RightsIssue::tag() const				{ return "RightsIssue"; }

std::string SchemeofArrangement::tag() const		{ return "SchemeofArrangement"; }
std::string ScripDividend::tag() const				{ return "ScripDividend"; }
std::string ScripIssue::tag() const					{ return "ScripIssue"; }
std::string Spinoff::tag() const					{ return "Spinoff"; }
std::string SpinOffWithElections::tag() const		{ return "SpinOffWithElections"; }
std::string StockDividend::tag() const				{ return "StockDividend"; }
std::string StockSplit::tag() const					{ return "StockSplit"; }
std::string SubscriptionOffer::tag() const			{ return "SubscriptionOffer"; }

std::string Takeover::tag() const					{ return "Takeover"; }
std::string TenderOffer::tag() const				{ return "TenderOffer"; }

std::string VoluntaryExchange::tag() const			{ return "VoluntaryExchange"; }
std::string Vote::tag() const						{ return "Vote"; }

std::string WarrantExercise::tag() const			{ return "WarrantExercise"; }
std::string WarrantExpiry::tag() const				{ return "WarrantExpiry"; }
std::string WarrantIssue::tag() const				{ return "WarrantIssue"; }

////////////////////////////////////////////////////////////////////////////////
// The message descriptions 
//

std::string Acquisition ::desc() const
{
	return "A company adopting a growth strategy, can use several means in order to seize control of other companies.";
}
std::string Ask::desc() const
{
	return "The price at which the owner of Equibit(s} is willing to sell the specified number of Equibits.";
}
std::string Assimilation::desc() const
{
	return "Absorption of a new issue of stock into the parent security where the original shares did not fully rank pari passu with the parent shares.  After the event, the assimilated shares rank pari passu with the parent.  Also referred to as funging of shares.";
}

std::string Bankruptcy::desc() const
{
	return "The company announces bankruptcy protection and the legal proceedings start in which it will be decided what pay-outs will be paid to stakeholders.";
}
std::string Bid::desc() const
{
	return "The price at which the market participant is will to pay for the specified number of Equibits.";
}
std::string BonusIssue::desc() const
{
	return "Shareholders are awarded additional securities (shares, rights or warrants} free of payment.The nominal value of shares does not change.";
}
std::string BonusRights::desc() const
{
	return "Distribution of rights which provide existing shareholders the privilege to subscribe to additional shares at a discounted rate. This corporate action has similar features to a bonus and rights issue.";
}
std::string BuyBackProgram::desc() const
{
	return "Offer by the issuing company to existing shareholders to repurchase the company’s own shares or other securities convertible into shares.  This results in a reduction in the number of outstanding shares.";
}

std::string CashDividend::desc() const
{
	return "The company pays out a cash amount to distribute its profits to shareholders.";
}
std::string CashStockOption::desc() const
{
	return "Shareholders are offered the choice to receive the dividend in cash or in additional new shares of the company (at a discount to market}. Reinvesting often carries a tax shield.";
}
std::string ClassAction::desc() const
{
	return "A lawsuit is being made against the company (usually by a large group of shareholders or by a representative person or organisation} that may result in a payment to the shareholders.";
}
std::string ConversionOfConvertibleBonds::desc() const
{
	return "Convertible bonds are being converted in the underlying shares.";
}
std::string CouponPayment::desc() const
{
	return "The issuer of the bond pays interst according to the terms and conditions of the bond, ie interest rate and intervals of payment.";
}

std::string Delisting::desc() const
{
	return "The company announces that it securities will no longer be listed on a stock exchange and that they will be booked out.";
}
std::string DeMerger::desc() const
{
	return "One company de-merges itself into 2 or more companies. The shares of the old company are booked out and the shares of the new companies will be booked in according to a set ratio.";
}
std::string DividendReinvestmentPlan::desc() const
{
	return "Similar to cash stock option. In this case however, the company first pays the cash dividend after which shareholders are offered the possibility to reinvest the cash dividend in new shares.";
}
std::string DutchAuction::desc() const
{
	return "A Dutch Auction Offer specifies a price range within which a fixed number of shares will ultimately be purchased. Shareholders are asked to submit instructions as to what price they are willing to sell. Once all instructions have been counted, the shares of the shareholders who voted to sell at the lowest prices will be bought untill either the fixed number of shares is reached or the upper limit of the price range is reached.";
}
	
std::string EarlyRedemption::desc() const
{
	return "The issuer of the bond repays the nominal prior to the maturity date of the bond, normally with accrued interest.";
}
	
std::string FinalRedemption::desc() const
{
	return "The issuer of the bond repays the nominal of the bond, normally with accrued interest.";
}

std::string GeneralAnnouncement::desc() const
{
	return "An event used by the company to notify its shareholders of any events that take place. This event type is used to communicate several types of information to the shareholders.";
}

std::string InitialPublicOffering::desc() const
{
	return "This is the first corporate actions event in the history of any company. The first time that a company gets listed on a stock exchange is regarded as an event in itself. Underwriters will try to get as many buyers for the newly listed shares for a price as high as possible. Any shares they can not sell, will be bought by the underwriters.";
}

std::string Liquidation::desc() const
{
	return "Liquidation proceedings consist of a distribution of cash and/or assets. Debt may be paid in order of priority based on preferred claims to assets specified by the security e.g. ordinary shares versus preferred shares.";
}

std::string Lottery::desc() const
{
	return "The issuer redeems selected holdings before the maturity date of the bond (early redemption}.";
}
std::string MandatoryExchange::desc() const
{
	return "Conversion of securities (generally convertible bonds or preferred shares} into a set number of other forms of securities (usually common shares).";
}
std::string Merger::desc() const
{
	return "Merger of 2 or more companies into one new company. The shares of the old companies are consequently exchanged into shares in the new company according to a set ratio.";
}
std::string MergerWithElections::desc() const
{
	return "Merger of 2 or more companies into one new company. The shares of the old companies are consequently exchanged into shares in the new company according to a set ratio. Shareholders of both companies are offered choices regarding the securities they receive";
}
std::string NameChange::desc() const
{
	return "Name changes are normally proposed and approved at the Company’s General meeting.  This has no effect on the capital and shareholder’s of the company.";
}
std::string OddLotTender::desc() const
{
	return "In case shares are tradeable in so called board lots of for example 100 shares only and a shareholder has an amount of shares that is not a multiple of the board lot, then this additional quantity is called odd lot. An odd lot tender is an offer to shareholders with odd lots to sell the shares in the odd lot at a given price. So for example, if the board lot is 100 and a shareholder holds 150 shares, an odd lot tender will give the shareholder to dispose of 50 shares at a given price. The board lot of 100 will still be tradable as normal.";
}
std::string OptionalPut::desc() const
{
	return "An event in which the holder of the put options has the option to exercise the put option in order to sell the underlying security at a given price.";
}
std::string OtherEvent::desc() const
{
	return "Any event that does not fit any of the other descriptions.";
}
std::string PartialRedemption::desc() const
{
	return "The issuer of the bond repays part of the nominal prior to maturity, normally with accrued interest.";
}
std::string ParValueChange::desc() const
{
	return "Similar to stock splits where the share nominal value is changed which normally results in a change in the number of shares held.";
}
std::string Private::desc() const
{
	return "A private message";
}
std::string ReturnOfCapital::desc() const
{
	return "A cash amount will be paid to investors in combination with a nominal value change of the shares.";
}
std::string ReverseStockSplit::desc() const
{
	return "The number of outstanding shares of the company gets reduced by an ‘X’ number while the nominal value of the shares increases by ‘X’. For example a ‘BMW' 1 for 2 reverse stock split, where the BMW shares’ nominal value increases from EUR 0.50 to EUR 1.00. The total value of the outstanding shares remains the same.";
}
std::string RightsAuction::desc() const
{
	return "Rights to buy new shares are being auctioned - shareholders who submit the highest prices at which they are willing to buy new shares will get the new shares.";
}
std::string RightsIssue::desc() const
{
	return "Rights are issued to entitled shareholders of the underlying stock.  They allow the rights holder to subscribe to additional shares of either the same stock or another stock or convertible bond, at the predetermined rate/ratio and price (usually at a discount to the market rate}. Rights are normally tradable and can be sold/bought in the market, exercised or lapsed.";
}
std::string SchemeofArrangement::desc() const
{
	return "Occurs when a parent company takes over its subsidiaries and distributes proceeds to its shareholders.";
}
std::string ScripDividend::desc() const
{
	return "The UK version of an optional dividend.  No stock dividends / coupons are issued but the shareholder can elect to receive either cash or new shares based on the ratio or by the net dividend divided by the re-investment price.  The default is always cash.";
}
std::string ScripIssue::desc() const
{
	return "Shareholders are awarded additional securities (shares, rights or warrants} free of payment.  The nominal value of shares does not change";
}
std::string Spinoff::desc() const
{
	return "A distribution of subsidiary stock to the shareholders of the parent corporation without having cost to the shareholder of the parent issue.";
}
std::string SpinOffWithElections::desc() const
{
	return "A distribution of subsidiary stock to the shareholders of the parent corporation without having cost to the shareholder of the parent issue whereby the shareholders are offered choices regarding the resultant stock.";
}
std::string StockDividend::desc() const
{
	return "Almost identical to bonus issues where additional shares in either the same or different stock is issued to shareholders of the underlying stock. ";
}

std::string StockSplit::desc() const
{
	return "A stock split is a division of the company shares into ‘X’ number of new shares with a nominal value of ‘1/X’ of the original share.  For example a ‘BMW’ 2 for 1 stock split, where a BMW share par value decreases to EUR 0.50 from EUR 1.00, whilst the number of share doubles. The total value of the outstanding shares remains the same.";
}
std::string SubscriptionOffer::desc() const
{
	return "Offer to existing shareholders to subscribe to new stock or convertible bonds";
}

std::string Takeover::desc() const
{
	return "One company taking control over another company (usually by acquiring the majority of outstanding share voting rights.";
}
std::string TenderOffer::desc() const
{
	return "Offer from Company A to shareholders of Company B to tender their shares to company A at a given price. The given price can be payable in cash only, stock in Company B only or a combination of cash and stock.";
}
std::string VoluntaryExchange::desc() const
{
	return "Offer to exchange shares of security A into cash or into Security B.";
}
std::string Vote::desc() const
{
	return "Share holder response to company referendum.";
}
std::string Poll::desc() const
{
	return "Every publicly traded company has an annual general meeting where management presents several decisions that need shareholder approval. The approval is given by means of voting for or against each decision. Shareholders may attend the meeting in person or vote by proxy - electronically or by mail via their brokers and custodian.";
}
std::string WarrantExercise::desc() const
{
	return "An event in which the holder of the warrants has the option to exercise the warrant in accordance with the terms and conditions of the warrant.";
}
std::string WarrantExpiry::desc() const
{
	return "An event that notifies the holder of the warrant that the warrant is about to expire and the holder of the warrant is given the option to exercise the warrant.";
}
std::string WarrantIssue::desc() const
{
	return "Per share an amount of warrants is issued according to a specific ratio. The warrant can entitle to sell or buy the underlying security at a given price within a given timeframe.";
}

///////////////////////////////////////////////////////////////////////////////


CUserMessage	* CUserMessage::create( const std::string & tag, CDataStream & str )
{
	CUserMessage	* result = NULL;

	if( tag[0] == 'A' )
	{
		if( tag == "Acquisition" )				result = new Acquisition();
		else if( tag == "Ask" )					result = new Ask();
		else if( tag == "Assimilation" )		result = new Assimilation();
	}
	else if( tag[0] == 'B' )
	{
		if( tag == "Bankruptcy" )				result = new Bankruptcy();
		else if( tag == "Bid" )					result = new Bid();
		else if( tag == "BonusIssue" )			result = new BonusIssue();
		else if( tag == "BonusRights" )			result = new BonusRights();
		else if( tag == "BuyBackProgram" )		result = new BuyBackProgram();
	}
	else if( tag[0] == 'C' )
	{
		if( tag == "CashDividend" )				result = new CashDividend();
		else if( tag == "CashStockOption" )		result = new CashStockOption();
		else if( tag == "ClassAction" ) 		result = new ClassAction();
		else if( tag == "ConversionOfConvertibleBonds" )	result = new ConversionOfConvertibleBonds();
		else if( tag == "CouponPayment" )		result = new CouponPayment();
	}
	else if( tag[0] == 'D' )
	{
		if( tag == "Delisting" )				result = new Delisting();
		else if( tag == "DeMerger" )			result = new DeMerger();
		else if( tag == "DividendReinvestmentPlan" )	result = new DividendReinvestmentPlan();
		else if( tag == "DutchAuction" )		result = new DutchAuction();
	}
	else if( tag[0] == 'E' )
	{
		if( tag == "EarlyRedemption" )			result = new EarlyRedemption();
	}
	else if( tag[0] == 'F' )
	{
		if( tag == "FinalRedemption" )			result = new FinalRedemption();
	}
	else if( tag[0] == 'G' )
	{
		if( tag == "GeneralAnnouncement" )		result = new GeneralAnnouncement();
	}
	else if( tag[0] == 'I' )
	{
		if( tag == "InitialPublicOffering" )	result = new InitialPublicOffering();
	}
	else if( tag[0] == 'L' )
	{
		if( tag == "Liquidation" )				result = new Liquidation();
		else if( tag == "Lottery" )				result = new Lottery();
	}
	else if( tag[0] == 'M' )
	{
		if( tag == "MandatoryExchange" )		result = new MandatoryExchange();
		else if( tag == "Merger" )				result = new Merger();
		else if( tag == "MergerWithElections" )	result = new MergerWithElections();
	}
	else if( tag[0] == 'N' )
	{
		if( tag == "NameChange" )				result = new NameChange();
	}
	else if( tag[0] == 'O' )
	{
		if( tag == "OddLotTender" )				result = new OddLotTender();
		else if( tag == "OptionalPut" )			result = new OptionalPut();
		else if( tag == "OtherEvent" )			result = new OtherEvent();
	}
	else if( tag[0] == 'P' )
	{
		if( tag == "PartialRedemption" )		result = new PartialRedemption();
		else if( tag == "ParValueChange" )		result = new ParValueChange();
		else if( tag == "Poll" )				result = new Poll();
		else if( tag == "Private" )				result = new Private();
	}
	else if( tag[0] == 'R' )
	{
		if( tag == "ReturnOfCapital" )			result = new ReturnOfCapital();
		else if( tag == "ReverseStockSplit" )	result = new ReverseStockSplit();
		else if( tag == "RightsAuction" )		result = new RightsAuction();
		else if( tag == "RightsIssue" )			result = new RightsIssue();
	}
	else if( tag[0] == 'S' )
	{
		if( tag == "SchemeofArrangement" )		result = new SchemeofArrangement();
		else if( tag == "ScripDividend" )		result = new ScripDividend();
		else if( tag == "ScripIssue" )			result = new ScripIssue();
		else if( tag == "Spinoff" )				result = new Spinoff();
		else if( tag == "SpinOffWithElections" )result = new SpinOffWithElections();
		else if( tag == "StockDividend" )		result = new StockDividend();
		else if( tag == "StockSplit" )			result = new StockSplit();
		else if( tag == "SubscriptionOffer" )	result = new SubscriptionOffer();
	}
	else if( tag[0] == 'T' )
	{
		if( tag == "Takeover" )					result = new Takeover();
		else if( tag == "TenderOffer" )			result = new TenderOffer();
	}
	else if( tag[0] == 'V' )
	{
		if( tag == "VoluntaryExchange" )		result = new VoluntaryExchange();
		else if( tag == "Vote" )				result = new Vote();
	}
	else if( tag[0] == 'W' )
	{
		if( tag == "WarrantExercise" )			result = new WarrantExercise();
		else if( tag == "WarrantExpiry" )		result = new WarrantExpiry();
		else if( tag == "WarrantIssue" )		result = new WarrantIssue();
	}

	if( !result )
		throw std::runtime_error( "CUserMessage::create(): unsupported message tag " + tag );

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
