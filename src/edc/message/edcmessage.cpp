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
#include "edc/rpc/edcwot.h"
#include "edc/rpc/edcserver.h"
#ifdef USE_HSM
#include "Thales/interface.h"
#include <secp256k1.h>
#include "edc/edcparams.h"

namespace
{
secp256k1_context   * secp256k1_context_verify;

struct Verifier
{
    Verifier()
    {
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    }
    ~Verifier()
    {
        secp256k1_context_destroy(secp256k1_context_verify);
    }
};

Verifier    verifier;

}

#endif


////////////////////////////////////////////////////////////////////////////////
// The message tags
//

const std::string CAcquisition::tag					= "Acquisition";
const std::string CAsk::tag							= "Ask";
const std::string CAssimilation::tag				= "Assimilation";

const std::string CBankruptcy::tag					= "Bankruptcy";
const std::string CBid::tag							= "Bid";
const std::string CBonusIssue::tag					= "BonusIssue";
const std::string CBonusRights::tag					= "BonusRights";
const std::string CBuyBackProgram::tag				= "BuyBackProgram";

const std::string CCashDividend::tag				= "CashDividend";
const std::string CCashStockOption::tag				= "CashStockOption";
const std::string CClassAction::tag					= "ClassAction";
const std::string CConversionOfConvertibleBonds::tag= "ConversionOfConvertibleBonds";
const std::string CCouponPayment::tag				= "CouponPayment";
const std::string CCreateWoTcertificate::tag		= "CreateWoTcertificate";

const std::string CDelisting::tag					= "Delisting";
const std::string CDeMerger::tag					= "DeMerger";
const std::string CDividendReinvestmentPlan::tag	= "DividendReinvestmentPlan";
const std::string CDutchAuction::tag				= "DutchAuction";

const std::string CEarlyRedemption::tag				= "EarlyRedemption";

const std::string CFinalRedemption::tag				= "FinalRedemption";

const std::string CGeneralAnnouncement::tag			= "GeneralAnnouncement";
const std::string CGeneralProxy::tag				= "GeneralProxy";

const std::string CInitialPublicOffering::tag		= "InitialPublicOffering";
const std::string CIssuerProxy::tag					= "IssuerProxy";

const std::string CLiquidation::tag					= "Liquidation";
const std::string CLottery::tag						= "Lottery";

const std::string CMandatoryExchange::tag			= "MandatoryExchange";
const std::string CMerger::tag						= "Merger";
const std::string CMergerWithElections::tag			= "MergerWithElections";

const std::string CNameChange::tag					= "NameChange";

const std::string COddLotTender::tag				= "OddLotTender";
const std::string COptionalPut::tag					= "OptionalPut";
const std::string COtherEvent::tag					= "OtherEvent";

const std::string CPartialRedemption::tag			= "PartialRedemption";
const std::string CParValueChange::tag				= "ParValueChange";
const std::string CPoll::tag						= "Poll";
const std::string CPollProxy::tag					= "PollProxy";
const std::string CPrivate::tag						= "Private";

const std::string CRequestWoTcertificate::tag		= "RequestWoTcertificate";
const std::string CReturnOfCapital::tag				= "ReturnOfCapital"; 
const std::string CReverseStockSplit::tag			= "ReverseStockSplit";
const std::string CRevokeGeneralProxy::tag			= "RevokeGeneralProxy";
const std::string CRevokeIssuerProxy::tag			= "RevokeIssuerProxy";
const std::string CRevokePollProxy::tag				= "RevokePollProxy";
const std::string CRevokeWoTcertificate::tag		= "RevokeWoTcertificate";
const std::string CRightsAuction::tag				= "RightsAuction";
const std::string CRightsIssue::tag					= "RightsIssue";

const std::string CSchemeofArrangement::tag			= "SchemeofArrangement";
const std::string CScripDividend::tag				= "ScripDividend";
const std::string CScripIssue::tag					= "ScripIssue";
const std::string CSpinoff::tag						= "Spinoff";
const std::string CSpinOffWithElections::tag		= "SpinOffWithElections";
const std::string CStockDividend::tag				= "StockDividend";
const std::string CStockSplit::tag					= "StockSplit";
const std::string CSubscriptionOffer::tag			= "SubscriptionOffer";

const std::string CTakeover::tag					= "Takeover";
const std::string CTenderOffer::tag					= "TenderOffer";

const std::string CVoluntaryExchange::tag			= "VoluntaryExchange";
const std::string CVote::tag						= "Vote";

const std::string CWarrantExercise::tag				= "WarrantExercise";
const std::string CWarrantExpiry::tag				= "WarrantExpiry";
const std::string CWarrantIssue::tag				= "WarrantIssue";

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

std::string CRequestWoTcertificate::desc() const
{
	return "Request a peer to create a WoT certificate";
}

std::string CRevokeWoTcertificate::desc() const
{
	return "Notify peer that a WoT certificate was revoked";
}

std::string CCreateWoTcertificate::desc() const
{
	return "Notify peer that a WoT certificate was created";
}

std::string CGeneralProxy::desc() const
{
	return "Grant general proxy voting privileges";
}

std::string CIssuerProxy::desc() const
{
	return "Grant proxy voting privileges on polls from a given Issuer";
}

std::string CPollProxy::desc() const
{
	return "Grant proxy voting privileges on a specific poll";
}

std::string CRevokeGeneralProxy::desc() const
{
	return "Revoke general proxy voting privileges";
}

std::string CRevokeIssuerProxy::desc() const
{
	return "Revoke general proxy voting privileges";
}

std::string CRevokePollProxy::desc() const
{
	return "Revoke proxy voting privileges on a specific poll";
}

///////////////////////////////////////////////////////////////////////////////

namespace
{
CUserMessage * strToObj( const std::string & tag )
{
	using T = std::pair<const std::string *, std::function<CUserMessage * ()> >;

	T msgMap [] =
	{
		{&CAcquisition::tag,			[]() { return new CAcquisition(); } },
		{&CAsk::tag,					[]() { return new CAsk(); } },
		{&CAssimilation::tag,			[]() { return new CAssimilation(); } },

		{&CBankruptcy::tag,				[]() { return new CBankruptcy(); } },
		{&CBid::tag,					[]() { return new CBid(); } },
		{&CBonusIssue::tag,				[]() { return new CBonusIssue(); } },
		{&CBonusRights::tag,			[]() { return new CBonusRights(); } },
		{&CBuyBackProgram::tag,			[]() { return new CBuyBackProgram(); } },

		{&CCashDividend::tag,			[]() { return new CCashDividend(); } },
		{&CCashStockOption::tag,		[]() { return new CCashStockOption(); } },
		{&CClassAction::tag,			[]() { return new CClassAction(); } },
		{&CConversionOfConvertibleBonds::tag, []() { return new CConversionOfConvertibleBonds();}},
		{&CCouponPayment::tag,			[]() { return new CCouponPayment(); } },
		{&CCreateWoTcertificate::tag,	[]() { return new CCreateWoTcertificate(); } },

		{&CDelisting::tag,				[]() { return new CDelisting(); } },
		{&CDeMerger::tag,				[]() { return new CDeMerger(); } },
		{&CDividendReinvestmentPlan::tag, []() { return new CDividendReinvestmentPlan(); } },
		{&CDutchAuction::tag,			[]() { return new CDutchAuction(); } },

		{&CEarlyRedemption::tag,		[]() { return new CEarlyRedemption(); } },

		{&CFinalRedemption::tag,		[]() { return new CFinalRedemption(); } },

		{&CGeneralAnnouncement::tag,	[]() { return new CGeneralAnnouncement(); } },
		{&CGeneralProxy::tag,			[]() { return new CGeneralProxy(); } },

		{&CInitialPublicOffering::tag,	[]() { return new CInitialPublicOffering(); } },
		{&CIssuerProxy::tag,			[]() { return new CIssuerProxy(); } },

		{&CLiquidation::tag,			[]() { return new CLiquidation(); } },
		{&CLottery::tag,				[]() { return new CLottery(); } },

		{&CMandatoryExchange::tag,		[]() { return new CMandatoryExchange(); } },
		{&CMerger::tag,					[]() { return new CMerger(); } },
		{&CMergerWithElections::tag,	[]() { return new CMergerWithElections(); } },

		{&CNameChange::tag,				[]() { return new CNameChange(); } },

		{&COddLotTender::tag,			[]() { return new COddLotTender(); } },
		{&COptionalPut::tag,			[]() { return new COptionalPut(); } },
		{&COtherEvent::tag,				[]() { return new COtherEvent(); } },

		{&CPartialRedemption::tag,		[]() { return new CPartialRedemption(); } },
		{&CParValueChange::tag,			[]() { return new CParValueChange(); } },
		{&CPoll::tag,					[]() { return new CPoll(); } },
		{&CPollProxy::tag,				[]() { return new CPollProxy(); } },
		{&CPrivate::tag,				[]() { return new CPrivate(); } },

		{&CReturnOfCapital::tag,		[]() { return new CReturnOfCapital(); } },
		{&CReverseStockSplit::tag,		[]() { return new CReverseStockSplit(); } },
		{&CRightsAuction::tag,			[]() { return new CRightsAuction(); } },
		{&CRightsIssue::tag,			[]() { return new CRightsIssue(); } },
		{&CRequestWoTcertificate::tag,	[]() { return new CRequestWoTcertificate(); } },
		{&CRevokeGeneralProxy::tag,		[]() { return new CRevokeGeneralProxy(); } },
		{&CRevokeIssuerProxy::tag,		[]() { return new CRevokeIssuerProxy(); } },
		{&CRevokePollProxy::tag,		[]() { return new CRevokePollProxy(); } },
		{&CRevokeWoTcertificate::tag,	[]() { return new CRevokeWoTcertificate(); } },

		{&CSchemeofArrangement::tag,	[]() { return new CSchemeofArrangement(); } },
		{&CScripDividend::tag,			[]() { return new CScripDividend(); } },
		{&CScripIssue::tag,				[]() { return new CScripIssue(); } },
		{&CSpinoff::tag,				[]() { return new CSpinoff(); } },
		{&CSpinOffWithElections::tag,	[]() { return new CSpinOffWithElections(); } },
		{&CStockDividend::tag,			[]() { return new CStockDividend(); } },
		{&CStockSplit::tag,				[]() { return new CStockSplit(); } },
		{&CSubscriptionOffer::tag,		[]() { return new CSubscriptionOffer(); } },

		{&CTakeover::tag,				[]() { return new CTakeover(); } },
		{&CTenderOffer::tag,			[]() { return new CTenderOffer(); } },

		{&CVoluntaryExchange::tag,		[]() { return new CVoluntaryExchange(); } },
		{&CVote::tag,					[]() { return new CVote(); } },

		{&CWarrantExercise::tag,		[]() { return new CWarrantExercise(); } },
		{&CWarrantExpiry::tag,			[]() { return new CWarrantExpiry(); } },
		{&CWarrantIssue::tag,			[]() { return new CWarrantIssue(); } },
	};

	auto it = lower_bound( begin(msgMap), end(msgMap), tag,
		[&]( const T & val, const std::string & tag ) { return *val.first < tag; } );

	if( it != end(msgMap))
		return it->second();

	return NULL;
}

void signMessage(
			  const CKeyID & keyID,    // IN
			const timespec & ts, 	   // IN
					uint64_t nonce,	   // IN
		 const std::string & type,     // IN
		 const std::string & assetId,  // IN
std::vector<unsigned char> & message,  // IN
std::vector<unsigned char> & vchSig    // OUT
    )
{
    EDCapp & theApp = EDCapp::singleton();

    CKey key;
    if (!theApp.walletMain()->GetKey(keyID, key))
	{
#ifdef USE_HSM
		EDCparams & params = EDCparams::singleton();

		std::string hsmID;
		if( params.usehsm && theApp.walletMain()->GetHSMKey( keyID, hsmID ))
		{
    		CHashWriter ss(SER_GETHASH, 0);
		    ss	<< edcstrMessageMagic
	   		 	<< ts.tv_sec
	   			<< ts.tv_nsec
	   			<< nonce
			    << type
			    << assetId
			    << message;

		    if (!NFast::sign( *theApp.nfHardServer(), *theApp.nfModule(), 
			hsmID, ss.GetHash().begin(), 256, vchSig ))
        		throw std::runtime_error("Sign failed");

            secp256k1_ecdsa_signature sig;
            memcpy( sig.data, vchSig.data(), sizeof(sig.data));

			secp256k1_ecdsa_signature_normalize( secp256k1_context_verify, &sig, &sig );
	
            vchSig.resize(72);
            size_t nSigLen = 72;

            secp256k1_ecdsa_signature_serialize_der( secp256k1_context_verify, (unsigned char*)&vchSig[0], &nSigLen,&sig);
            vchSig.resize(nSigLen);
            vchSig.push_back((unsigned char)SIGHASH_ALL);
			return;
		}
#endif
        throw std::runtime_error("Private key not available");
	}

    CHashWriter ss(SER_GETHASH, 0);
    ss << edcstrMessageMagic
	   << ts.tv_sec
	   << ts.tv_nsec
	   << nonce
       << type
       << assetId
       << message;

    if (!key.Sign(ss.GetHash(), vchSig ))
        throw std::runtime_error("Sign failed");
}

bool verifyMessage(
					const CKeyID & keyID,    // IN
				  const timespec & ts, 	   	 // IN
						  uint64_t nonce,	 // IN
			   const std::string & type,     // IN
			   const std::string & assetId,  // IN
const std::vector<unsigned char> & message,  // IN
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
	if( CUserMessage * result = strToObj( tag ))
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
	ans->data_.resize(data.size() );

	auto i = data.begin();
	auto ui= ans->data_.begin();
	auto ue= ans->data_.end();

	while( ui != ue )
	{
		*ui = *i;
		++i;
		++ui;
	}

	signMessage(sender,
				ans->timestamp_,
				ans->nonce_,
		 		type,
		 		receiver.ToString(),
		 		ans->data_,
				ans->signature_ );

	return ans;
}

CMulticast * CMulticast::create(
			   const std::string & type, 
			        const CKeyID & sender, 
			   const std::string & issuer, 
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
	ans->issuerAddr_ = issuer;
	ans->data_.resize(data.size() );
	
	auto i = data.begin();
	auto ui= ans->data_.begin();
	auto ue= ans->data_.end();

	while( ui != ue )
	{
		*ui = *i;
		++i;
		++ui;
	}

	signMessage(sender,
				ans->timestamp_,
				ans->nonce_,
		 		type,
		 		issuer,
		 		ans->data_,
				ans->signature_ );
	return ans;
}

CBroadcast * CBroadcast::create(
			   const std::string & type, 
	     	        const CKeyID & sender, 
			   const std::string & data )
{
	CBroadcast * ans = dynamic_cast<CBroadcast *>(strToObj( type ));

	if(!ans)
	{
		std::string msg = "Invalid broadcast message type:";
		msg += type;
		throw std::runtime_error( msg );
	}

	ans->proofOfWork();

	ans->senderAddr_ = sender;
	ans->data_.resize(data.size() );

	auto i = data.begin();
	auto ui= ans->data_.begin();
	auto ue= ans->data_.end();

	while( ui != ue )
	{
		*ui = *i;
		++i;
		++ui;
	}

	signMessage(sender,
				ans->timestamp_,
				ans->nonce_,
		 		type,
		 		"",
		 		ans->data_,
				ans->signature_ );
	return ans;
}

CBroadcast * CBroadcast::create(
			   const std::string & type, 
	     	        const CKeyID & sender, 
const std::vector<unsigned char> & data )
{
	CBroadcast * ans = dynamic_cast<CBroadcast *>(strToObj( type ));

	if(!ans)
	{
		std::string msg = "Invalid broadcast message type:";
		msg += type;
		throw std::runtime_error( msg );
	}

	ans->proofOfWork();

	ans->senderAddr_ = sender;
	ans->data_.resize(data.size());
	std::copy( data.begin(), data.end(), ans->data_.begin() );

	signMessage(sender,
				ans->timestamp_,
				ans->nonce_,
		 		type,
		 		"",
		 		ans->data_,
				ans->signature_ );
	return ans;
}

///////////////////////////////////////////////////////////////////////////

namespace
{

std::string toString( const std::vector<unsigned char> & in )
{
	std::string ans;

	auto i = in.begin();
	auto e = in.end();

	while( i != e )
	{
		if(std::isprint(*i))
			ans += static_cast<char>(*i);
		else
		{
			char buff[3];
			sprintf( buff, "%%%2.2d", *i );
			ans += buff;	
		}
			
		++i;
	}

	return ans;
}

}

std::string	CUserMessage::ToString() const
{
	std::stringstream out;

	out << "sender=" << senderAddr_.ToString()
		<< " timestamp=" << timestamp_.tv_sec << ":" << timestamp_.tv_nsec
		<< " nonce=" << nonce_
		<< " data=[" << toString(data_) << "]"
		<< " signature=" << HexStr(signature_);

	return out.str();
}

std::string	CPeerToPeer::ToString() const
{
	std::string ans = vtag();
	ans += ":";
	ans += CUserMessage::ToString();

	ans += " receiver=";
	ans += receiverAddr_.ToString();

	return ans;
}

std::string	CMulticast::ToString() const
{
	std::string ans = vtag();
	ans += ":";
	ans += CUserMessage::ToString();

	ans += " issuer=";
	ans += issuerAddr_;

	return ans;
}

std::string	CBroadcast::ToString() const
{
	std::string ans = vtag();
	ans += ":";
	ans += CUserMessage::ToString();

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
		<< ", \"data\":\"" << toString(data_) << "\""
		<< ", \"signature\":\"" << HexStr(signature_) << "\"";

	return out.str();
}

std::string	CPeerToPeer::ToJSON() const
{
	std::string ans = "{\"type\":\"";
	ans += vtag();
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
	ans += vtag();
	ans += "\"";
	ans += CUserMessage::ToJSON();

	ans += ", \"issuer\":\"";
	ans += issuerAddr_;
	ans += "\"}";

	return ans;
}

std::string	CBroadcast::ToJSON() const
{
	std::string ans = "{\"type\":\"";
	ans += vtag();
	ans += "\"";
	ans += CUserMessage::ToJSON();

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
		 	vtag(),
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
		 	vtag(),
		 	issuerAddr_,
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
		 	vtag(),
		 	"",
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

///////////////////////////////////////////////////////////////////////////

void CCreateWoTcertificate::extract(
	CPubKey & pubkey,
	CPubKey & sPubkey,
	WoTCertificate & cert ) const
{
	uint16_t	pLen  = *reinterpret_cast<const uint16_t *>(data_.data());
	uint16_t	spLen = *reinterpret_cast<const uint16_t *>(data_.data()+sizeof(uint16_t));
	uint16_t	cLen  = *reinterpret_cast<const uint16_t *>(data_.data()+sizeof(uint16_t)*2);

	const unsigned char * p = data_.data() + sizeof(uint16_t)*3;

	pubkey.Set( p, p + pLen );
	p += pLen;

	pubkey.Set( p, p + spLen );
	p += spLen;

	CDataStream	ss( reinterpret_cast<const char *>(p), reinterpret_cast<const char *>(p+cLen), 
		SER_NETWORK, PROTOCOL_VERSION );
	ss >> cert;
}

void CRevokeWoTcertificate::extract(
	CPubKey & pubkey,
	CPubKey & sPubkey,
	std::string & reason ) const
{
	uint16_t	pLen  = *reinterpret_cast<const uint16_t *>(data_.data());
	uint16_t	spLen = *reinterpret_cast<const uint16_t *>(data_.data()+sizeof(uint16_t));
	uint16_t	rLen  = *reinterpret_cast<const uint16_t *>(data_.data()+sizeof(uint16_t)*2);

	const unsigned char * p = data_.data() + sizeof(uint16_t)*3;

	pubkey.Set( p, p + pLen );
	p += pLen;

	pubkey.Set( p, p + spLen );
	p += spLen;

	const unsigned char * end = p + rLen;

	while( p != end )
	{
		reason += static_cast<char>(*p);
		++p;
	}
}


void CUserMessage::process( CEDCWallet & wallet )
{
	wallet.AddMessage( vtag(), GetHash(), this );
}

void CCreateWoTcertificate::process( CEDCWallet & wallet )
{
    CPubKey pubkey;
    CPubKey sPubkey;
    WoTCertificate cert;

    extract( pubkey, sPubkey, cert );

    wallet.AddWoTCertificate( pubkey, sPubkey, cert );
}

void CRevokeWoTcertificate::process( CEDCWallet & wallet )
{
    CPubKey pubkey;
    CPubKey sPubkey;
    std::string reason;

    extract( pubkey, sPubkey, reason );

    wallet.RevokeWoTCertificate( pubkey, sPubkey, reason );
}

namespace
{

void extract( 
	std::vector<unsigned char> & data, 
	std::string & addr, 
	std::string & paddr )
{
	auto d = data.begin();

	auto alen = *d++;
	addr.resize(alen);

	auto i = addr.begin();
	auto e = addr.end();
	while( i != e )
		*i++ = *d++;

	auto plen = *d++;
	paddr.resize(plen);

	i = paddr.begin();
	e = paddr.end();
	while( i != e )
		*i++ = *d++;
}

void extract( 
	std::vector<unsigned char> & data, 
	std::string & addr, 
	std::string & paddr,
	std::string & other )
{
	auto d = data.begin();

	auto len = *d++;
	addr.resize(len);

	auto i = addr.begin();
	auto e = addr.end();
	while( i != e )
		*i++ = *d++;

	len = *d++;
	paddr.resize(len);

	i = paddr.begin();
	e = paddr.end();
	while( i != e )
		*i++ = *d++;

	len = *d++;
	other.resize(len);

	i = other.begin();
	e = other.end();
	while( i != e )
		*i++ = *d++;
}

}

void CGeneralProxy::process( CEDCWallet & wallet )
{
	LOCK2(EDC_cs_main, wallet.cs_wallet);

	edcEnsureWalletIsUnlocked();

	std::string addr;
	std::string paddr;
	extract( data_, addr, paddr );

	std::string errStr;
    bool rc = wallet.AddGeneralProxy( addr, paddr, errStr );
	if(!rc)
		error( errStr.c_str() );
}

void CIssuerProxy::process( CEDCWallet & wallet )
{
	LOCK2(EDC_cs_main, wallet.cs_wallet);

	edcEnsureWalletIsUnlocked();

	std::string addr;
	std::string paddr;
	std::string iaddr;
	extract( data_, addr, paddr, iaddr );

	std::string errStr;
    bool rc = wallet.AddIssuerProxy( addr, paddr, iaddr, errStr );
	if(!rc)
		error( errStr.c_str() );
}

void CPollProxy::process( CEDCWallet & wallet )
{
	LOCK2(EDC_cs_main, wallet.cs_wallet);

	edcEnsureWalletIsUnlocked();

	std::string addr;
	std::string paddr;
	std::string pollID;
	extract( data_, addr, paddr, pollID );

	std::string errStr;
    bool rc = wallet.AddPollProxy( addr, paddr, pollID, errStr );
	if(!rc)
		error( errStr.c_str() );
}

void CRevokeGeneralProxy::process( CEDCWallet & wallet )
{
	LOCK2(EDC_cs_main, wallet.cs_wallet);

	edcEnsureWalletIsUnlocked();

	std::string addr;
	std::string paddr;
	extract( data_, addr, paddr );

	std::string errStr;
    bool rc = wallet.AddGeneralProxyRevoke( addr, paddr, errStr );
	if(!rc)
		error( errStr.c_str() );
}

void CRevokeIssuerProxy::process( CEDCWallet & wallet )
{
	LOCK2(EDC_cs_main, wallet.cs_wallet);

	edcEnsureWalletIsUnlocked();

	std::string addr;
	std::string paddr;
	std::string iaddr;
	extract( data_, addr, paddr, iaddr );

	std::string errStr;
    bool rc = wallet.AddIssuerProxyRevoke( addr, paddr, iaddr, errStr );
	if(!rc)
		error( errStr.c_str() );
}

void CRevokePollProxy::process( CEDCWallet & wallet )
{
	LOCK2(EDC_cs_main, wallet.cs_wallet);

	edcEnsureWalletIsUnlocked();

	std::string addr;
	std::string paddr;
	std::string pollID;
	extract( data_, addr, paddr, pollID );

	std::string errStr;
    bool rc = wallet.AddPollProxyRevoke( addr, paddr, pollID, errStr );
	if(!rc)
		error( errStr.c_str() );
}

void CPoll::process( CEDCWallet & wallet )
{
    // TODO: CPoll::process()
}

void CVote::process( CEDCWallet & wallet )
{
    // TODO: CVote::process()
}
