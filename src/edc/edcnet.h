// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "net.h"
#include "amount.h"
#include "edc/edcbloom.h"
#include "compat.h"
#include "limitedmap.h"
#include "edcnetbase.h"
#include "edcprotocol.h"
#include "random.h"
#include "streams.h"
#include "sync.h"
#include "uint256.h"

#include <atomic>
#include <deque>
#include <stdint.h>

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include <boost/filesystem/path.hpp>
#include <boost/foreach.hpp>
#include <boost/signals2/signal.hpp>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


class CAddrMan;
class CScheduler;
class CEDCNode;
class CUserMessage;

namespace boost 
{
    class thread_group;
}

unsigned int edcReceiveFloodSize();
unsigned int edcSendBufferSize();

typedef int NodeId;

void edcAddressCurrentlyConnected(const CService& addr);
void edcMapPort(bool fUseUPnP);
unsigned short edcGetListenPort();
unsigned short edcGetListenSecurePort();
bool edcBindListenPort(const CService &bindAddr, std::string& strError, bool fWhitelisted = false);
void edcStartNode(boost::thread_group& threadGroup, CScheduler& scheduler);
bool edcStopNode();
void SocketSendData(CEDCNode *pnode);

// Signals for message handling
struct CEDCNodeSignals
{
    boost::signals2::signal<int ()> GetHeight;
    boost::signals2::signal<bool (CEDCNode*), CombinerAll> ProcessMessages;
    boost::signals2::signal<bool (CEDCNode*), CombinerAll> SendMessages;
    boost::signals2::signal<void (NodeId, const CEDCNode*)> InitializeNode;
    boost::signals2::signal<void (NodeId)> FinalizeNode;
};

CEDCNodeSignals& edcGetNodeSignals();

bool IsPeerAddrLocalGood(CEDCNode *pnode);
void AdvertiseLocal(CEDCNode *pnode);
bool edcIsLimited(enum Network net);
bool edcIsLimited(const CNetAddr& addr);
bool edcRemoveLocal(const CService& addr);
bool edcSeenLocal(const CService& addr);
bool edcIsLocal(const CService& addr);
bool edcIsReachable(enum Network net);
bool edcIsReachable(const CNetAddr &addr);
bool edcAddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);

typedef std::map<std::string, uint64_t> mapMsgCmdSize; //command, total bytes

typedef std::map<CSubNet, CBanEntry> banmap_t;

/** Information about a peer */
class CEDCNode
{
public:
    // socket
    ServiceFlags nServices;
	ServiceFlags nServicesExpected;
    CDataStream ssSend;
    size_t nSendSize; // total size of all vSendMsg entries
    size_t nSendOffset; // offset inside the first vSendMsg already sent
    uint64_t nSendBytes;
    std::deque<CSerializeData> vSendMsg;
    CCriticalSection cs_vSend;

    std::deque<CInv> vRecvGetData;
    std::deque<CNetMessage> vRecvMsg;
    CCriticalSection cs_vRecvMsg;
    uint64_t nRecvBytes;
    int nRecvVersion;

    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    const CAddress addr;
    std::string addrName;
    CService addrLocal;
    int nVersion;
    // strSubVer is whatever byte array we read from the wire. However, this field is intended
    // to be printed out, displayed to humans in various forms and so on. So we sanitize it and
    // store the sanitized version in cleanSubVer. The original should be used when dealing with
    // the network or wire types and the cleaned string used when displayed or logged.
    std::string strSubVer, cleanSubVer;
    bool fWhitelisted; // This peer can bypass DoS banning.
	bool fFeeler; // If true this node is being used as a short lived feeler.
    bool fOneShot;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fSuccessfullyConnected;
    bool fDisconnect;
    // We use fRelayTxes for two purposes -
    // a) it allows us to not relay tx invs before receiving the peer's version message
    // b) the peer may tell us in its version message that we should not relay tx invs
    //    unless it loads a bloom filter.
    bool fRelayTxes; //protected by cs_filter
    bool fSentAddr;
    CSemaphoreGrant grantOutbound;
    CCriticalSection cs_filter;
    CEDCBloomFilter* pfilter;
    int nRefCount;
    NodeId id;

	const uint64_t nKeyedNetGroup;
protected:

    // Denial-of-service detection/prevention
    // Key is IP address, value is banned-until-time
    static banmap_t setBanned;
    static CCriticalSection cs_setBanned;
    static bool setBannedIsDirty;

    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    static std::vector<CSubNet> vWhitelistedRange;
    static CCriticalSection cs_vWhitelistedRange;

    mapMsgCmdSize mapSendBytesPerMsgCmd;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;

    // Basic fuzz-testing
    void Fuzz(int nChance); // modifies ssSend

public:
    uint256 hashContinue;
    int nStartingHeight;

    // flood relay
    std::vector<CAddress> vAddrToSend;
    CRollingBloomFilter addrKnown;
    bool fGetAddr;
    std::set<uint256> setKnown;
    int64_t nNextAddrSend;
    int64_t nNextLocalAddrSend;

    // inventory based relay
    CRollingBloomFilter filterInventoryKnown;

    // Set of transaction ids we still have to announce.
    // They are sorted by the mempool before relay, so the order is not important.
    std::set<uint256> setInventoryTxToSend;

    // List of block ids we still have announce.
    // There is no final sorting before sending, as they are always sent immediately
    // and in the order requested.
    std::vector<uint256> vInventoryBlockToSend;

    CCriticalSection cs_inventory;
    std::set<uint256> setAskFor;
    std::multimap<int64_t, CInv> mapAskFor;
    int64_t nNextInvSend;

    // Used for headers announcements - unfiltered blocks to relay
    // Also protected by cs_inventory
    std::vector<uint256> vBlockHashesToAnnounce;

    // Used for BIP35 mempool sending, also protected by cs_inventory
    bool fSendMempool;

    // Last time a "MEMPOOL" request was serviced.
    std::atomic<int64_t> timeLastMempoolReq;

    // Block and TXN accept times
    std::atomic<int64_t> nLastBlockTime;
    std::atomic<int64_t> nLastTXTime;

    // Ping time measurement:
    // The pong reply we're expecting, or 0 if no pong expected.
    uint64_t nPingNonceSent;

    // Time (in usec) the last ping was sent, or 0 if no ping was ever sent.
    int64_t nPingUsecStart;

    // Last measured round-trip time.
    int64_t nPingUsecTime;

    // Best measured round-trip time.
    int64_t nMinPingUsecTime;

    // Whether a ping is requested.
    bool fPingQueued;

    // Minimum fee rate with which to filter inv's to this node
    CAmount minFeeFilter;

    CCriticalSection cs_feeFilter;
    CAmount lastSentFeeFilter;
    int64_t nextSendTimeFeeFilter;

    CCriticalSection cs_userMessage;
	std::vector<CUserMessage *>	vUserMessages;

    CEDCNode(SOCKET hSocketIn, const CAddress &addrIn, const std::string &addrNameIn = "", bool fInboundIn = false);
    virtual ~CEDCNode();

	SOCKET	socket() const 			{ return hSocket; }
	bool	invalidSocket() const	{ return hSocket == INVALID_SOCKET; }

	virtual void	closeSocket();
	virtual ssize_t send(const void *buf, size_t len, int flags);
	virtual ssize_t recv(void *buf, size_t len, int flags);

	void init();

protected:

    SOCKET hSocket;

private:

    // Network usage totals
    static CCriticalSection cs_totalBytesRecv;
    static CCriticalSection cs_totalBytesSent;
    static uint64_t nTotalBytesRecv;
    static uint64_t nTotalBytesSent;

    // outbound limit & stats
    static uint64_t nMaxOutboundTotalBytesSentInCycle;
    static uint64_t nMaxOutboundCycleStartTime;
    static uint64_t nMaxOutboundLimit;
    static uint64_t nMaxOutboundTimeframe;

    CEDCNode(const CEDCNode&);
    void operator=(const CEDCNode&);

	static uint64_t CalculateKeyedNetGroup(const CAddress& ad);

public:

    NodeId GetId() const 
	{
      return id;
    }

    int GetRefCount()
    {
        assert(nRefCount >= 0);
        return nRefCount;
    }

	// requires LOCK(cs_vRecvMsg)
    unsigned int GetTotalRecvSize()
    {
        unsigned int total = 0;
        BOOST_FOREACH(const CNetMessage &msg, vRecvMsg)
            total += msg.vRecv.size() + 24;
        return total;
    }

	// requires LOCK(cs_vRecvMsg)
    bool ReceiveMsgBytes(const char *pch, unsigned int nBytes);

	// requires LOCK(cs_vRecvMsg)
    void SetRecvVersion(int nVersionIn)
    {
        nRecvVersion = nVersionIn;
        BOOST_FOREACH(CNetMessage &msg, vRecvMsg)
            msg.SetVersion(nVersionIn);
    }

    CEDCNode* AddRef()
    {
        nRefCount++;
        return this;
    }

    void Release()
    {
        nRefCount--;
    }

    void AddAddressKnown(const CAddress& _addr)
    {
        addrKnown.insert(_addr.GetKey());
    }

    void PushAddress(const CAddress& _addr)
    {
        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        if (_addr.IsValid() && !addrKnown.contains(_addr.GetKey())) 
		{
            if (vAddrToSend.size() >= MAX_ADDR_TO_SEND) 
			{
                vAddrToSend[insecure_rand() % vAddrToSend.size()] = _addr;
            } 
			else 
			{
                vAddrToSend.push_back(_addr);
            }
        }
    }

    void AddInventoryKnown(const CInv& inv)
    {
        {
            LOCK(cs_inventory);
            filterInventoryKnown.insert(inv.hash);
        }
    }

    void PushInventory(const CInv& inv)
    {
       LOCK(cs_inventory);
       if (inv.type == MSG_TX) 
       {
            if (!filterInventoryKnown.contains(inv.hash)) 
            {
                setInventoryTxToSend.insert(inv.hash);
            }
        } 
        else if (inv.type == MSG_BLOCK) 
        {
            vInventoryBlockToSend.push_back(inv.hash);
        }
    }

	void PushUserMessage( CUserMessage * um )
	{
		LOCK(cs_userMessage);
		vUserMessages.push_back(um);
	}

    void PushBlockHash(const uint256 &hash)
    {
        LOCK(cs_inventory);
        vBlockHashesToAnnounce.push_back(hash);
    }

    void AskFor(const CInv& inv);

    // TODO: Document the postcondition of this function.  Is cs_vSend locked?
    void BeginMessage(const char* pszCommand) EXCLUSIVE_LOCK_FUNCTION(cs_vSend);

    // TODO: Document the precondition of this function.  Is cs_vSend locked?
    void AbortMessage() UNLOCK_FUNCTION(cs_vSend);

    // TODO: Document the precondition of this function.  Is cs_vSend locked?
    void EndMessage(const char* pszCommand) UNLOCK_FUNCTION(cs_vSend);

    void PushVersion();


    void PushMessage(const char* pszCommand)
    {
        try
        {
            BeginMessage(pszCommand);
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1>
    void PushMessage(const char* pszCommand, const T1& a1)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    /** Send a message containing a1, serialized with flag flag. */
    template<typename T1>
    void PushMessageWithFlag(int flag, const char* pszCommand, const T1& a1)
    {
        try
        {
            BeginMessage(pszCommand);
            WithOrVersion(&ssSend, flag) << a1;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8, const T9& a9)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9;
            EndMessage(pszCommand);
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    void CloseSocketDisconnect();

    // Denial-of-service detection/prevention
    // The idea is to detect peers that are behaving
    // badly and disconnect/ban them, but do it in a
    // one-coding-mistake-won't-shatter-the-entire-network
    // way.
    // IMPORTANT:  There should be nothing I can give a
    // node that it will forward on that will make that
    // node's peers drop it. If there is, an attacker
    // can isolate a node and/or try to split the network.
    // Dropping a node for sending stuff that is invalid
    // now but might be valid in a later version is also
    // dangerous, because it can cause a network split
    // between nodes running old code and nodes running
    // new code.
    static void ClearBanned(); // needed for unit testing
    static bool IsBanned(CNetAddr ip);
    static bool IsBanned(CSubNet subnet);
    static void Ban(const CNetAddr &ip, const BanReason &banReason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    static void Ban(const CSubNet &subNet, const BanReason &banReason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    static bool Unban(const CNetAddr &ip);
    static bool Unban(const CSubNet &ip);
    static void GetBanned(banmap_t &banmap);
    static void SetBanned(const banmap_t &banmap);

    //!check is the banlist has unwritten changes
    static bool BannedSetIsDirty();
    //!set the "dirty" flag for the banlist
    static void SetBannedSetDirty(bool dirty=true);
    //!clean unused entries (if bantime has expired)
    static void SweepBanned();

    void copyStats(CNodeStats &stats);

    static bool IsWhitelistedRange(const CNetAddr &ip);
    static void AddWhitelistedRange(const CSubNet &subnet);

    // Network stats
    static void RecordBytesRecv(uint64_t bytes);
    static void RecordBytesSent(uint64_t bytes);

    static uint64_t GetTotalBytesRecv();
    static uint64_t GetTotalBytesSent();

    //!set the max outbound target in bytes
    static void SetMaxOutboundTarget(uint64_t limit);
    static uint64_t GetMaxOutboundTarget();

    //!set the timeframe for the max outbound target
    static void SetMaxOutboundTimeframe(uint64_t timeframe);
    static uint64_t GetMaxOutboundTimeframe();

    //!check if the outbound target is reached
    // if param historicalBlockServingLimit is set true, the function will
    // response true if the limit for serving historical blocks has been reached
    static bool OutboundTargetReached(bool historicalBlockServingLimit);

    //!response the bytes left in the current max outbound cycle
    // in case of no limit, it will always response 0
    static uint64_t GetOutboundTargetBytesLeft();

    //!response the time in second left in the current max outbound cycle
    // in case of no limit, it will always response 0
    static uint64_t GetMaxOutboundTimeLeftInCycle();
};


class CEDCSSLNode : public CEDCNode
{
public:
    CEDCSSLNode(SOCKET hSocketIn, const CAddress &addrIn, const std::string &addrNameIn, bool fInboundIn, SSL * = NULL );


	virtual void	closeSocket();

	virtual ssize_t send(const void *buf, size_t len, int flags );
	virtual ssize_t recv(void *buf, size_t len, int flags);

	// Server SSL accept processing
	static SSL * sslAccept(SOCKET);

	// Client SSL connectt processing
	static SSL * sslConnect(SOCKET);

private:
    CEDCSSLNode(const CEDCNode & );
    void operator=(const CEDCSSLNode & );

	SSL * ssl_;
};

class CEDCTransaction;
void RelayTransaction(const CEDCTransaction& tx);

class CUserMessage;
void RelayUserMessage( CUserMessage *, bool );

/** Access to the (IP) address database (peers.dat) */
class CEDCAddrDB
{
private:
    boost::filesystem::path pathAddr;

public:
    CEDCAddrDB();
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
	bool Read(CAddrMan& addr, CDataStream& ssPeers);
};

/** Access to the banlist database (banlist.dat) */
class CEDCBanDB
{
private:
    boost::filesystem::path pathBanlist;
public:
    CEDCBanDB();
    bool Write(const banmap_t& banSet);
    bool Read(banmap_t& banSet);
};

/** Return a timestamp in the future (in microseconds) for exponentially distributed events. */
int64_t edcPoissonNextSend(int64_t nNow, int average_interval_seconds);

CEDCNode * edcFindNode(const CNetAddr& ip, bool );
CEDCNode * edcFindNode(const CSubNet& subNet, bool );
CEDCNode * edcFindNode(const std::string& addrName, bool );
CEDCNode * edcFindNode(const CService& ip, bool );
CEDCNode * edcFindNode( const NodeId id, bool ); //TODO: Remove this
bool edcOpenNetworkConnection( const CAddress & addrConnect, bool fCountFailure, CSemaphoreGrant * grantOutbound  = NULL, CSemaphoreGrant * sgrantOutbound  = NULL, const char * pszDest = NULL, bool fOneShot = false, bool fFeeler = false ); 
void edcSetLimited(enum Network net, bool fLimited);
std::vector<AddedNodeInfo> edcGetAddedNodeInfo();
