// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "net.h"
#include "edcaddrdb.h"
#include "addrman.h"
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
class CEDCConnman;

namespace boost 
{
    class thread_group;
}

unsigned int edcReceiveFloodSize();
unsigned int edcSendBufferSize();

typedef int NodeId;

void edcMapPort(bool fUseUPnP);
unsigned short edcGetListenPort();
unsigned short edcGetListenSecurePort();
bool edcBindListenPort(const CService &bindAddr, std::string& strError, bool fWhitelisted = false);
void SocketSendData(CEDCNode *pnode);

// Signals for message handling
struct CEDCNodeSignals
{
    boost::signals2::signal<int ()> GetHeight;
    boost::signals2::signal<bool (CEDCNode *, CEDCConnman &), CombinerAll> ProcessMessages;
    boost::signals2::signal<bool (CEDCNode *, CEDCConnman &), CombinerAll> SendMessages;
    boost::signals2::signal<void (NodeId, const CEDCNode *)> InitializeNode;
    boost::signals2::signal<void (NodeId, bool&)> FinalizeNode;
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

    CEDCNode(NodeId id, SOCKET hSocketIn, const CAddress &addrIn, const std::string &addrNameIn = "", bool fInboundIn = false);
    virtual ~CEDCNode();

	SOCKET	socket() const 			{ return hSocket; }
	bool	invalidSocket() const	{ return hSocket == INVALID_SOCKET; }

	virtual void	closeSocket();
	virtual ssize_t send(const void *buf, size_t len, int flags);
	virtual ssize_t recv(void *buf, size_t len, int flags);

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

	uint64_t nLocalHostNonce;
public:

    NodeId GetId() const 
	{
      return id;
    }

	uint64_t GetLocalNonce() const
	{
		return nLocalHostNonce;
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

    void copyStats(CNodeStats &stats);

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
    CEDCSSLNode( NodeId id, SOCKET hSocketIn, const CAddress &addrIn, const std::string &addrNameIn, bool fInboundIn, SSL * = NULL );


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
class CUserMessage;

void RelayUserMessage( CUserMessage *, bool );

/** Return a timestamp in the future (in microseconds) for exponentially distributed events. */
int64_t edcPoissonNextSend(int64_t nNow, int average_interval_seconds);


class CEDCConnman
{
public:

    enum NumConnections 
	{
        CONNECTIONS_NONE = 0,
        CONNECTIONS_IN = (1U << 0),
        CONNECTIONS_OUT = (1U << 1),
        CONNECTIONS_ALL = (CONNECTIONS_IN | CONNECTIONS_OUT),
    };

    CEDCConnman();
    ~CEDCConnman();

    bool Start(boost::thread_group& threadGroup, CScheduler& scheduler, std::string& strNodeError);
    void Stop();
	bool BindListenPort(const CService &bindAddr, std::string& strError, bool fWhitelisted = false);

	bool OpenNetworkConnection( const CAddress & addrConnect, bool fCountFailure, CSemaphoreGrant * grantOutbound  = NULL, CSemaphoreGrant * sgrantOutbound  = NULL, const char * pszDest = NULL, bool fOneShot = false, bool fFeeler = false ); 
	bool CheckIncomingNonce(uint64_t nonce);

    bool ForNode(NodeId id, std::function<bool(CEDCNode* pnode)> func);
    bool ForEachNode(std::function<bool(CEDCNode* pnode)> func);
    bool ForEachNode(std::function<bool(const CEDCNode* pnode)> func) const;
    bool ForEachNodeThen(std::function<bool(CEDCNode* pnode)> pre, std::function<void()> post);
    bool ForEachNodeThen(std::function<bool(const CEDCNode* pnode)> pre, std::function<void()> post) const;

    void RelayTransaction(const CEDCTransaction& tx);

    // Addrman functions
    size_t GetAddressCount() const;
    void SetServices(const CService &addr, ServiceFlags nServices);
    void MarkAddressGood(const CAddress& addr);
    void AddNewAddress(const CAddress& addr, const CAddress& addrFrom, int64_t nTimePenalty = 0);
    void AddNewAddresses(const std::vector<CAddress>& vAddr, const CAddress& addrFrom, int64_t nTimePenalty = 0);
    std::vector<CAddress> GetAddresses();
    void AddressCurrentlyConnected(const CService& addr);
	void RelayUserMessage( CUserMessage * um, bool secure );

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
    void Ban(const CNetAddr& netAddr, const BanReason& reason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    void Ban(const CSubNet& subNet, const BanReason& reason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    void ClearBanned(); // needed for unit testing
    bool IsBanned(CNetAddr ip);
    bool IsBanned(CSubNet subnet);
    bool Unban(const CNetAddr &ip);
    bool Unban(const CSubNet &ip);
    void GetBanned(banmap_t &banmap);
    void SetBanned(const banmap_t &banmap);

	void AddOneShot(const std::string & strDest);

    bool AddNode(const std::string& node);
    bool RemoveAddedNode(const std::string& node);
    std::vector<AddedNodeInfo> GetAddedNodeInfo();

    size_t GetNodeCount(NumConnections num);
    void GetNodeStats(std::vector<CNodeStats>& vstats);
    bool DisconnectAddress(const CNetAddr& addr);
    bool DisconnectNode(const std::string& node);
    bool DisconnectNode(NodeId id);
    bool DisconnectSubnet(const CSubNet& subnet);

	void AddWhitelistedRange(const CSubNet &subnet);
private:
    struct ListenSocket 
	{
        SOCKET socket;
        bool whitelisted;

        ListenSocket(SOCKET socket_, bool whitelisted_) : socket(socket_), whitelisted(whitelisted_) {}
    };

    void ThreadOpenAddedConnections();
    void ProcessOneShot();
    void ThreadOpenConnections();
    void ThreadMessageHandler();
    void AcceptConnection(const ListenSocket& hListenSocket);
    void ThreadSocketHandler();
    void ThreadDNSAddressSeed();

    CEDCNode* FindNode(const CNetAddr& ip, bool );
    CEDCNode* FindNode(const CSubNet& subNet, bool );
    CEDCNode* FindNode(const std::string& addrName, bool );
    CEDCNode* FindNode(const CService& addr, bool );

    bool AttemptToEvictConnection();

	CEDCNode* ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure);
    bool IsWhitelistedRange(const CNetAddr &addr);

	void DeleteNode( CEDCNode * pnode );

    NodeId GetNewNodeId();

    //!check is the banlist has unwritten changes
    bool BannedSetIsDirty();
    //!set the "dirty" flag for the banlist
    void SetBannedSetDirty(bool dirty=true);
    //!clean unused entries (if bantime has expired)
    void SweepBanned();
    void DumpAddresses();
    void DumpData();
    void DumpBanlist();

    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    std::vector<CSubNet> vWhitelistedRange;
    CCriticalSection cs_vWhitelistedRange;

	std::vector<ListenSocket> vhListenSocket;
    banmap_t setBanned;
    CCriticalSection cs_setBanned;
    bool setBannedIsDirty;
    bool fAddressesInitialized;
    CAddrMan addrman;
    std::deque<std::string> vOneShots;
    CCriticalSection cs_vOneShots;

    std::vector<CEDCNode*>    vNodes;
    std::vector<CEDCSSLNode*> vSSLNodes;
    mutable CCriticalSection  cs_vNodes;
	std::atomic<NodeId>       nLastNodeId;
};

void edcSetLimited(enum Network net, bool fLimited);

bool edcStartNode(CEDCConnman & connman, boost::thread_group & threadGroup, CScheduler & scheduler, std::string & strNodeError);
bool edcStopNode(CEDCConnman & connman);
