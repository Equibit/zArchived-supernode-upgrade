// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "edcnet.h"
#include "edcparams.h"
#include "edcutil.h"
#include "edcapp.h"

#include "addrman.h"
#include "edcchainparams.h"
#include "clientversion.h"
#include "edc/consensus/edcconsensus.h"
#include "crypto/common.h"
#include "hash.h"
#include "edc/primitives/edctransaction.h"
#include "scheduler.h"
#include "edcui_interface.h"
#include "utilstrencodings.h"
#include "edc/message/edcmessage.h"
#include "edc/wallet/edcwallet.h"

#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

#ifdef USE_UPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <math.h>

// Dump addresses to peers.dat and banlist.dat every 15 minutes (900s)
#define DUMP_ADDRESSES_INTERVAL 900

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

// Fix for ancient MinGW versions, that don't have defined these in ws2tcpip.h.
// Todo: Can be removed when our pull-tester is upgraded to a modern MinGW version.
#ifdef WIN32
#ifndef PROTECTION_LEVEL_UNRESTRICTED
#define PROTECTION_LEVEL_UNRESTRICTED 10
#endif
#ifndef IPV6_PROTECTION_LEVEL
#define IPV6_PROTECTION_LEVEL 23
#endif
#endif

using namespace std;

namespace 
{
    const int MAX_OUTBOUND_CONNECTIONS = 8;

    struct ListenSocket 
	{
        SOCKET socket;
        bool whitelisted;

        ListenSocket(SOCKET socket, bool whitelisted) : socket(socket), whitelisted(whitelisted) {}
    };
}

const static std::string NET_MESSAGE_COMMAND_OTHER = "*other*";

namespace
{
bool vfLimited[NET_MAX] = {};
CEDCNode* pnodeLocalHost = NULL;
std::vector<ListenSocket> vhListenSocket;
deque<pair<int64_t, uint256> > relayExpiration;
}

bool edcfAddressesInitialized = false;

static deque<string> vOneShots;
CCriticalSection edccs_vOneShots;

set<CNetAddr> edcsetservAddNodeAddresses;
CCriticalSection edccs_setservAddNodeAddresses;

static CSemaphore *semOutbound = NULL;
boost::condition_variable edcmessageHandlerCondition;

// Signals for message handling
static CEDCNodeSignals g_signals;
CEDCNodeSignals& edcGetNodeSignals() { return g_signals; }


unsigned short edcGetListenPort()
{
	EDCparams & params = EDCparams::singleton();
    return static_cast<unsigned short>(params.port);
}

// find 'best' local address for a particular peer
bool edcGetLocal(CService& addr, const CNetAddr *paddrPeer)
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();

    if (!params.listen)
        return false;

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(theApp.mapLocalHostCS());
        for (map<CNetAddr, LocalServiceInfo>::iterator it = theApp.mapLocalHost().begin(); it != theApp.mapLocalHost().end(); it++)
        {
            int nScore = (*it).second.nScore;
            int nReachability = (*it).first.GetReachabilityFrom(paddrPeer);
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
            {
                addr = CService((*it).first, (*it).second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

//! Convert the pnSeeds6 array into usable address objects.
static std::vector<CAddress> convertSeed6(const std::vector<SeedSpec6> &vSeedsIn)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    std::vector<CAddress> vSeedsOut;
    vSeedsOut.reserve(vSeedsIn.size());
    for (std::vector<SeedSpec6>::const_iterator i(vSeedsIn.begin()); i != vSeedsIn.end(); ++i)
    {
        struct in6_addr ip;
        memcpy(&ip, i->addr, sizeof(ip));
        CAddress addr(CService(ip, i->port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
    return vSeedsOut;
}

int64_t edcGetAdjustedTime();

// get best local address for a particular peer as a CAddress
// Otherwise, return the unroutable 0.0.0.0 but filled in with
// the normal parameters, since the IP may be changed to a useful
// one by discovery.
CAddress edcGetLocalAddress(const CNetAddr *paddrPeer)
{
    CAddress ret(CService("0.0.0.0",edcGetListenPort()),0);
    CService addr;
    if (edcGetLocal(addr, paddrPeer))
    {
        ret = CAddress(addr);
    }
	EDCapp & theApp = EDCapp::singleton();
    ret.nServices = theApp.localServices();
    ret.nTime = edcGetAdjustedTime();
    return ret;
}

int edcGetnScore(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    if (theApp.mapLocalHost().count(addr) == LOCAL_NONE)
        return 0;
    return theApp.mapLocalHost()[addr].nScore;
}

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CEDCNode *pnode)
{
	EDCparams & params = EDCparams::singleton();
    return params.discover && pnode->addr.IsRoutable() && pnode->addrLocal.IsRoutable() &&
           !edcIsLimited(pnode->addrLocal.GetNetwork());
}

// pushes our own address to a peer
void AdvertiseLocal(CEDCNode *pnode)
{
	EDCparams & params = EDCparams::singleton();

    if (params.listen && pnode->fSuccessfullyConnected)
    {
        CAddress addrLocal = edcGetLocalAddress(&pnode->addr);
        // If discovery is enabled, sometimes give our peer the address it
        // tells us that it sees us as in case it has a better idea of our
        // address than we do.
        if (IsPeerAddrLocalGood(pnode) && (!addrLocal.IsRoutable() ||
             GetRand((edcGetnScore(addrLocal) > LOCAL_MANUAL) ? 8:2) == 0))
        {
            addrLocal.SetIP(pnode->addrLocal);
        }
        if (addrLocal.IsRoutable())
        {
            edcLogPrintf("AdvertiseLocal: advertising address %s\n", addrLocal.ToString());
            pnode->PushAddress(addrLocal);
        }
    }
}

bool edcRemoveLocal(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    edcLogPrintf("RemoveLocal(%s)\n", addr.ToString());
    theApp.mapLocalHost().erase(addr);
    return true;
}

/** Make a particular network entirely off-limits (no automatic connects to it) */
void edcSetLimited(enum Network net, bool fLimited)
{
	EDCapp & theApp = EDCapp::singleton();
    if (net == NET_UNROUTABLE)
        return;
    LOCK(theApp.mapLocalHostCS());
    vfLimited[net] = fLimited;
}

bool edcIsLimited(enum Network net)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    return vfLimited[net];
}

bool edcIsLimited(const CNetAddr &addr)
{
    return edcIsLimited(addr.GetNetwork());
}

/** vote for a local address */
bool edcSeenLocal(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    {
        LOCK(theApp.mapLocalHostCS());
        if (theApp.mapLocalHost().count(addr) == 0)
            return false;
        theApp.mapLocalHost()[addr].nScore++;
    }
    return true;
}


/** check whether a given address is potentially local */
bool edcIsLocal(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    return theApp.mapLocalHost().count(addr) > 0;
}

/** check whether a given network is one we can probably connect to */
bool edcIsReachable(enum Network net)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.mapLocalHostCS());
    return !vfLimited[net];
}

/** check whether a given address is in a network we can probably connect to */
bool edcIsReachable(const CNetAddr& addr)
{
    enum Network net = addr.GetNetwork();
    return edcIsReachable(net);
}

void edcAddressCurrentlyConnected(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    theApp.addrman().Connected(addr);
}


uint64_t CEDCNode::nTotalBytesRecv = 0;
uint64_t CEDCNode::nTotalBytesSent = 0;
CCriticalSection CEDCNode::cs_totalBytesRecv;
CCriticalSection CEDCNode::cs_totalBytesSent;

uint64_t CEDCNode::nMaxOutboundLimit = 0;
uint64_t CEDCNode::nMaxOutboundTotalBytesSentInCycle = 0;
uint64_t CEDCNode::nMaxOutboundTimeframe = 60*60*24; //1 day
uint64_t CEDCNode::nMaxOutboundCycleStartTime = 0;

CEDCNode* edcFindNode(const CNetAddr& ip)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.vNodesCS());
    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
        if ((CNetAddr)pnode->addr == ip)
            return (pnode);
    return NULL;
}

CEDCNode* edcFindNode(const CSubNet& subNet)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.vNodesCS());
    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
    if (subNet.Match((CNetAddr)pnode->addr))
        return (pnode);
    return NULL;
}

CEDCNode* edcFindNode(const std::string& addrName)
{	
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.vNodesCS());
    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
        if (pnode->addrName == addrName)
            return (pnode);
    return NULL;
}

CEDCNode* edcFindNode(const CService& addr)
{
	EDCapp & theApp = EDCapp::singleton();
    LOCK(theApp.vNodesCS());
    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
        if ((CService)pnode->addr == addr)
            return (pnode);
    return NULL;
}

CEDCNode* edcConnectNode(CAddress addrConnect, const char *pszDest)
{
    if (pszDest == NULL) 
	{
        if (edcIsLocal(addrConnect))
            return NULL;

        // Look for an existing connection
        CEDCNode* pnode = edcFindNode((CService)addrConnect);
        if (pnode)
        {
            pnode->AddRef();
            return pnode;
        }
    }

    /// debug print
    edcLogPrint("net", "trying connection %s lastseen=%.1fhrs\n",
        pszDest ? pszDest : addrConnect.ToString(),
        pszDest ? 0.0 : (double)(edcGetAdjustedTime() - addrConnect.nTime)/3600.0);

    // Connect
    SOCKET hSocket;
    bool proxyConnectionFailed = false;
	EDCapp & theApp = EDCapp::singleton();

    if (pszDest ? edcConnectSocketByName(addrConnect, hSocket, pszDest, edcParams().
		GetDefaultPort(), theApp.connectTimeout(), &proxyConnectionFailed) :
        edcConnectSocket(addrConnect, hSocket, theApp.connectTimeout(), 
		&proxyConnectionFailed))
    {
        if (!IsSelectableSocket(hSocket)) 
		{
            edcLogPrintf("Cannot create connection: non-selectable socket created (fd >= FD_SETSIZE ?)\n");
            CloseSocket(hSocket);
            return NULL;
        }

        theApp.addrman().Attempt(addrConnect);

        // Add node
        CEDCNode* pnode = new CEDCNode(hSocket, addrConnect, pszDest ? pszDest : "", false);
        pnode->AddRef();

        {
            LOCK(theApp.vNodesCS());
            theApp.vNodes().push_back(pnode);
        }

        pnode->nTimeConnected = GetTime();

        return pnode;
    } 
	else if (!proxyConnectionFailed) 
	{
        // If connecting to the node failed, and failure is not caused by a problem connecting to
        // the proxy, mark this as an attempt.
        theApp.addrman().Attempt(addrConnect);
    }

    edcLogPrint("net", "WARNING:FAILED to connect %s\n", pszDest ? pszDest : addrConnect.ToString());

    return NULL;
}

void CEDCNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    if (hSocket != INVALID_SOCKET)
    {
        edcLogPrint("net", "disconnecting peer=%d\n", id);
        CloseSocket(hSocket);
    }

    // in case this fails, we'll empty the recv buffer when the CEDCNode is deleted
    TRY_LOCK(cs_vRecvMsg, lockRecv);
    if (lockRecv)
        vRecvMsg.clear();
}

void CEDCNode::PushVersion()
{
    int nBestHeight = g_signals.GetHeight().get_value_or(0);

    int64_t nTime = (fInbound ? edcGetAdjustedTime() : GetTime());

    CAddress addrYou = (addr.IsRoutable() && !edcIsProxy(addr) ? addr : 
		CAddress(CService("0.0.0.0",0)));

    CAddress addrMe = edcGetLocalAddress(&addr);
	uint64_t localHostNonce;
    GetRandBytes((unsigned char*)&localHostNonce, sizeof(localHostNonce));
	EDCapp & theApp = EDCapp::singleton();
	theApp.localHostNonce( localHostNonce);

	EDCparams & params = EDCparams::singleton();

    if (params.logips)
        edcLogPrint("net", "send version message: version %d, blocks=%d, us=%s, them=%s, peer=%d\n", PROTOCOL_VERSION, nBestHeight, addrMe.ToString(), addrYou.ToString(), id);
    else
        edcLogPrint("net", "send version message: version %d, blocks=%d, us=%s, peer=%d\n", PROTOCOL_VERSION, nBestHeight, addrMe.ToString(), id);

    PushMessage(
		NetMsgType::VERSION, PROTOCOL_VERSION, theApp.localServices(), 
		nTime, 
		addrYou, 
		addrMe,
        localHostNonce, 
		theApp.strSubVersion(), 
		nBestHeight, 
		!params.blocksonly);
}

banmap_t CEDCNode::setBanned;
CCriticalSection CEDCNode::cs_setBanned;
bool CEDCNode::setBannedIsDirty;

void CEDCNode::ClearBanned()
{
    LOCK(cs_setBanned);
    setBanned.clear();
    setBannedIsDirty = true;
}

bool CEDCNode::IsBanned(CNetAddr ip)
{
    bool fResult = false;
    {
        LOCK(cs_setBanned);
        for (banmap_t::iterator it = setBanned.begin(); it != setBanned.end(); it++)
        {
            CSubNet subNet = (*it).first;
            CBanEntry banEntry = (*it).second;

            if(subNet.Match(ip) && GetTime() < banEntry.nBanUntil)
                fResult = true;
        }
    }
    return fResult;
}

bool CEDCNode::IsBanned(CSubNet subnet)
{
    bool fResult = false;
    {
        LOCK(cs_setBanned);
        banmap_t::iterator i = setBanned.find(subnet);
        if (i != setBanned.end())
        {
            CBanEntry banEntry = (*i).second;
            if (GetTime() < banEntry.nBanUntil)
                fResult = true;
        }
    }
    return fResult;
}

void CEDCNode::Ban(
	 const CNetAddr & addr, 
	const BanReason & banReason, 
			  int64_t bantimeoffset, 
				 bool sinceUnixEpoch) 
{
    CSubNet subNet(addr);
    Ban(subNet, banReason, bantimeoffset, sinceUnixEpoch);
}

void CEDCNode::Ban(
	  const CSubNet & subNet, 
	const BanReason & banReason, 
			  int64_t bantimeoffset, 
				 bool sinceUnixEpoch) 
{
    CBanEntry banEntry(GetTime());
    banEntry.banReason = banReason;
    if (bantimeoffset <= 0)
    {
		EDCparams & params = EDCparams::singleton();
        bantimeoffset = params.bantime;
        sinceUnixEpoch = false;
    }
    banEntry.nBanUntil = (sinceUnixEpoch ? 0 : GetTime() )+bantimeoffset;

    LOCK(cs_setBanned);
    if (setBanned[subNet].nBanUntil < banEntry.nBanUntil)
        setBanned[subNet] = banEntry;

    setBannedIsDirty = true;
}

bool CEDCNode::Unban(const CNetAddr &addr) 
{
    CSubNet subNet(addr);
    return Unban(subNet);
}

bool CEDCNode::Unban(const CSubNet &subNet) 
{
    LOCK(cs_setBanned);
    if (setBanned.erase(subNet))
    {
        setBannedIsDirty = true;
        return true;
    }
    return false;
}

void CEDCNode::GetBanned(banmap_t &banMap)
{
    LOCK(cs_setBanned);
    banMap = setBanned; //create a thread safe copy
}

void CEDCNode::SetBanned(const banmap_t &banMap)
{
    LOCK(cs_setBanned);
    setBanned = banMap;
    setBannedIsDirty = true;
}

void CEDCNode::SweepBanned()
{
    int64_t now = GetTime();

    LOCK(cs_setBanned);
    banmap_t::iterator it = setBanned.begin();
    while(it != setBanned.end())
    {
        CSubNet subNet = (*it).first;
        CBanEntry banEntry = (*it).second;
        if(now > banEntry.nBanUntil)
        {
            setBanned.erase(it++);
            setBannedIsDirty = true;
            edcLogPrint("net", "%s: Removed banned node ip/subnet from banlist.dat: %s\n", __func__, subNet.ToString());
        }
        else
            ++it;
    }
}

bool CEDCNode::BannedSetIsDirty()
{
    LOCK(cs_setBanned);
    return setBannedIsDirty;
}

void CEDCNode::SetBannedSetDirty(bool dirty)
{
    LOCK(cs_setBanned); //reuse setBanned lock for the isDirty flag
    setBannedIsDirty = dirty;
}


std::vector<CSubNet> CEDCNode::vWhitelistedRange;
CCriticalSection CEDCNode::cs_vWhitelistedRange;

bool CEDCNode::IsWhitelistedRange(const CNetAddr &addr) 
{
    LOCK(cs_vWhitelistedRange);
    BOOST_FOREACH(const CSubNet& subnet, vWhitelistedRange) 
	{
        if (subnet.Match(addr))
            return true;
    }
    return false;
}

void CEDCNode::AddWhitelistedRange(const CSubNet &subnet) 
{
    LOCK(cs_vWhitelistedRange);
    vWhitelistedRange.push_back(subnet);
}

#undef X
#define X(name) stats.name = name
void CEDCNode::copyStats(CNodeStats &stats)
{
    stats.nodeid = this->GetId();
    X(nServices);
    X(fRelayTxes);
    X(nLastSend);
    X(nLastRecv);
    X(nTimeConnected);
    X(nTimeOffset);
    X(addrName);
    X(nVersion);
    X(cleanSubVer);
    X(fInbound);
    X(nStartingHeight);
    X(nSendBytes);
    X(mapSendBytesPerMsgCmd);
    X(nRecvBytes);
    X(mapRecvBytesPerMsgCmd);
    X(fWhitelisted);

    // It is common for nodes with good ping times to suddenly become lagged,
    // due to a new block arriving or other large transfer.
    // Merely reporting pingtime might fool the caller into thinking the node was still responsive,
    // since pingtime does not update until the ping is complete, which might take a while.
    // So, if a ping is taking an unusually long time in flight,
    // the caller can immediately detect that this is happening.
    int64_t nPingUsecWait = 0;
    if ((0 != nPingNonceSent) && (0 != nPingUsecStart)) 
	{
        nPingUsecWait = GetTimeMicros() - nPingUsecStart;
    }

    // Raw ping time is in microseconds, but show it to user as whole seconds (Bitcoin users should be well used to small numbers with many decimal places by now :)
    stats.dPingTime = (((double)nPingUsecTime) / 1e6);
    stats.dPingMin  = (((double)nMinPingUsecTime) / 1e6);
    stats.dPingWait = (((double)nPingUsecWait) / 1e6);

    // Leave string empty if addrLocal invalid (not filled in yet)
    stats.addrLocal = addrLocal.IsValid() ? addrLocal.ToString() : "";
}
#undef X

// requires LOCK(cs_vRecvMsg)
bool CEDCNode::ReceiveMsgBytes(const char *pch, unsigned int nBytes)
{
    while (nBytes > 0) 
	{
        // get current incomplete message, or create a new one
        if (vRecvMsg.empty() ||
            vRecvMsg.back().complete())
            vRecvMsg.push_back(CNetMessage(edcParams().MessageStart(), SER_NETWORK, nRecvVersion));

        CNetMessage& msg = vRecvMsg.back();

        // absorb network data
        int handled;
        if (!msg.in_data)
            handled = msg.readHeader(pch, nBytes);
        else
            handled = msg.readData(pch, nBytes);

        if (handled < 0)
                return false;

        if (msg.in_data && msg.hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) 
		{
            edcLogPrint("net", "Oversized message from peer=%i, disconnecting\n", GetId());
            return false;
        }

        pch += handled;
        nBytes -= handled;

        if (msg.complete()) 
		{

            //store received bytes per message command
            //to prevent a memory DOS, only allow valid commands
            mapMsgCmdSize::iterator i = mapRecvBytesPerMsgCmd.find(msg.hdr.pchCommand);
            if (i == mapRecvBytesPerMsgCmd.end())
                i = mapRecvBytesPerMsgCmd.find(NET_MESSAGE_COMMAND_OTHER);
            assert(i != mapRecvBytesPerMsgCmd.end());
            i->second += msg.hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

            msg.nTime = GetTimeMicros();
            edcmessageHandlerCondition.notify_one();
        }
    }

    return true;
}

// requires LOCK(cs_vSend)
void SocketSendData(CEDCNode *pnode)
{
    std::deque<CSerializeData>::iterator it = pnode->vSendMsg.begin();

    while (it != pnode->vSendMsg.end()) 
	{
        const CSerializeData &data = *it;
        assert(data.size() > pnode->nSendOffset);
        int nBytes = send(pnode->hSocket, &data[pnode->nSendOffset], data.size() - pnode->nSendOffset, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (nBytes > 0) 
		{
            pnode->nLastSend = GetTime();
            pnode->nSendBytes += nBytes;
            pnode->nSendOffset += nBytes;
            pnode->RecordBytesSent(nBytes);

            if (pnode->nSendOffset == data.size()) 
			{
                pnode->nSendOffset = 0;
                pnode->nSendSize -= data.size();
                it++;
            } 
			else 
			{
                // could not send full message; stop sending more
                break;
            }
        } 
		else 
		{
            if (nBytes < 0) 
			{
                // error
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                {
                    edcLogPrintf("socket send error %s\n", NetworkErrorString(nErr));
                    pnode->CloseSocketDisconnect();
                }
            }
            // couldn't send anything at all
            break;
        }
    }

    if (it == pnode->vSendMsg.end()) 
	{
        assert(pnode->nSendOffset == 0);
        assert(pnode->nSendSize == 0);
    }
    pnode->vSendMsg.erase(pnode->vSendMsg.begin(), it);
}

static list<CEDCNode*> vNodesDisconnected;

class CEDCNodeRef 
{
public:
    CEDCNodeRef(CEDCNode *pnode) : _pnode(pnode) 
	{
		EDCapp & theApp = EDCapp::singleton();
        LOCK(theApp.vNodesCS());
        _pnode->AddRef();
    }

    ~CEDCNodeRef() 
	{
		EDCapp & theApp = EDCapp::singleton();
        LOCK(theApp.vNodesCS());
        _pnode->Release();
    }

    CEDCNode& operator *() const {return *_pnode;};
    CEDCNode* operator ->() const {return _pnode;};

    CEDCNodeRef& operator =(const CEDCNodeRef& other)
    {
		EDCapp & theApp = EDCapp::singleton();
        if (this != &other) 
		{
            LOCK(theApp.vNodesCS());

            _pnode->Release();
            _pnode = other._pnode;
            _pnode->AddRef();
        }
        return *this;
    }

    CEDCNodeRef(const CEDCNodeRef& other):
        _pnode(other._pnode)
    {
		EDCapp & theApp = EDCapp::singleton();
        LOCK(theApp.vNodesCS());
        _pnode->AddRef();
    }
private:
    CEDCNode *_pnode;
};

static bool ReverseCompareNodeMinPingTime(const CEDCNodeRef &a, const CEDCNodeRef &b)
{
    return a->nMinPingUsecTime > b->nMinPingUsecTime;
}

static bool ReverseCompareNodeTimeConnected(const CEDCNodeRef &a, const CEDCNodeRef &b)
{
    return a->nTimeConnected > b->nTimeConnected;
}

class CompareNetGroupKeyed
{
    std::vector<unsigned char> vchSecretKey;
public:
    CompareNetGroupKeyed()
    {
        vchSecretKey.resize(32, 0);
        GetRandBytes(vchSecretKey.data(), vchSecretKey.size());
    }

    bool operator()(const CEDCNodeRef &a, const CEDCNodeRef &b)
    {
        std::vector<unsigned char> vchGroupA, vchGroupB;
        CSHA256 hashA, hashB;
        std::vector<unsigned char> vchA(32), vchB(32);

        vchGroupA = a->addr.GetGroup();
        vchGroupB = b->addr.GetGroup();

        hashA.Write(begin_ptr(vchGroupA), vchGroupA.size());
        hashB.Write(begin_ptr(vchGroupB), vchGroupB.size());

        hashA.Write(begin_ptr(vchSecretKey), vchSecretKey.size());
        hashB.Write(begin_ptr(vchSecretKey), vchSecretKey.size());

        hashA.Finalize(begin_ptr(vchA));
        hashB.Finalize(begin_ptr(vchB));

        return vchA < vchB;
    }
};

/** Try to find a connection to evict when the node is full.
  *  Extreme care must be taken to avoid opening the node to attacker
  *   triggered network partitioning.
  *  The strategy used here is to protect a small number of peers
  *   for each of several distinct characteristics which are difficult
  *   to forge.  In order to partition a node the attacker must be
  *   simultaneously better at all of them than honest peers.
  */
static bool AttemptToEvictConnection(bool fPreferNewConnection) 
{
	EDCapp & theApp = EDCapp::singleton();
    std::vector<CEDCNodeRef> vEvictionCandidates;
    {
        LOCK(theApp.vNodesCS());

        BOOST_FOREACH(CEDCNode *node, theApp.vNodes()) 
		{
            if (node->fWhitelisted)
                continue;
            if (!node->fInbound)
                continue;
            if (node->fDisconnect)
                continue;
            vEvictionCandidates.push_back(CEDCNodeRef(node));
        }
    }

    if (vEvictionCandidates.empty()) return false;

    // Protect connections with certain characteristics

    // Deterministically select 4 peers to protect by netgroup.
    // An attacker cannot predict which netgroups will be protected.
    static CompareNetGroupKeyed comparerNetGroupKeyed;
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), comparerNetGroupKeyed);
    vEvictionCandidates.erase(vEvictionCandidates.end() - std::min(4, static_cast<int>(vEvictionCandidates.size())), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Protect the 8 nodes with the lowest minimum ping time.
    // An attacker cannot manipulate this metric without physically moving nodes closer to the target.
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), ReverseCompareNodeMinPingTime);
    vEvictionCandidates.erase(vEvictionCandidates.end() - std::min(8, static_cast<int>(vEvictionCandidates.size())), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Protect the half of the remaining nodes which have been connected the longest.
    // This replicates the non-eviction implicit behavior, and precludes attacks that start later.
    std::sort(vEvictionCandidates.begin(), vEvictionCandidates.end(), ReverseCompareNodeTimeConnected);
    vEvictionCandidates.erase(vEvictionCandidates.end() - static_cast<int>(vEvictionCandidates.size() / 2), vEvictionCandidates.end());

    if (vEvictionCandidates.empty()) return false;

    // Identify the network group with the most connections and youngest member.
    // (vEvictionCandidates is already sorted by reverse connect time)
    std::vector<unsigned char> naMostConnections;
    unsigned int nMostConnections = 0;
    int64_t nMostConnectionsTime = 0;
    std::map<std::vector<unsigned char>, std::vector<CEDCNodeRef> > mapAddrCounts;
    BOOST_FOREACH(const CEDCNodeRef &node, vEvictionCandidates) 
	{
        mapAddrCounts[node->addr.GetGroup()].push_back(node);
        int64_t grouptime = mapAddrCounts[node->addr.GetGroup()][0]->nTimeConnected;
        size_t groupsize = mapAddrCounts[node->addr.GetGroup()].size();

        if (groupsize > nMostConnections || (groupsize == nMostConnections && grouptime > nMostConnectionsTime)) 
		{
            nMostConnections = groupsize;
            nMostConnectionsTime = grouptime;
            naMostConnections = node->addr.GetGroup();
        }
    }

    // Reduce to the network group with the most connections
    vEvictionCandidates = mapAddrCounts[naMostConnections];

    // Do not disconnect peers if there is only one unprotected connection from their network group.
    // This step excessively favors netgroup diversity, and should be removed once more protective criteria are established.
    if (vEvictionCandidates.size() <= 1)
        // unless we prefer the new connection (for whitelisted peers)
        if (!fPreferNewConnection)
            return false;

    // Disconnect from the network group with the most connections
    vEvictionCandidates[0]->fDisconnect = true;

    return true;
}

static void AcceptConnection(const ListenSocket& hListenSocket) 
{
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    SOCKET hSocket = accept(hListenSocket.socket, (struct sockaddr*)&sockaddr, &len);
    CAddress addr;
    int nInbound = 0;
	EDCapp & theApp = EDCapp::singleton();
    int nMaxInbound = theApp.maxConnections() - MAX_OUTBOUND_CONNECTIONS;

    if (hSocket != INVALID_SOCKET)
        if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr))
            edcLogPrintf("Warning: Unknown socket family\n");

    bool whitelisted = hListenSocket.whitelisted || CEDCNode::IsWhitelistedRange(addr);
    {
        LOCK(theApp.vNodesCS());
        BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
            if (pnode->fInbound)
                nInbound++;
    }

    if (hSocket == INVALID_SOCKET)
    {
        int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK)
            edcLogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
        return;
    }

    if (!IsSelectableSocket(hSocket))
    {
        edcLogPrintf("connection from %s dropped: non-selectable socket\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    // According to the internet TCP_NODELAY is not carried into accepted sockets
    // on all platforms.  Set it again here just to be sure.
    int set = 1;
#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

    if (CEDCNode::IsBanned(addr) && !whitelisted)
    {
        edcLogPrintf("connection from %s dropped (banned)\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    if (nInbound >= nMaxInbound)
    {
        if (!AttemptToEvictConnection(whitelisted)) 
		{
            // No connection to evict, disconnect the new connection
            edcLogPrint("net", "failed to find an eviction candidate - connection dropped (full)\n");
            CloseSocket(hSocket);
            return;
        }
    }

    CEDCNode* pnode = new CEDCNode(hSocket, addr, "", true);
    pnode->AddRef();
    pnode->fWhitelisted = whitelisted;

    edcLogPrint("net", "connection from %s accepted\n", addr.ToString());

    {
        LOCK(theApp.vNodesCS());
        theApp.vNodes().push_back(pnode);
    }
}

void edcThreadSocketHandler()
{
	EDCapp & theApp = EDCapp::singleton();
    unsigned int nPrevNodeCount = 0;
    while (true)
    {
        //
        // Disconnect nodes
        //
        {
            LOCK(theApp.vNodesCS());
            // Disconnect unused nodes
            vector<CEDCNode*> vNodesCopy = theApp.vNodes();
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
            {
                if (pnode->fDisconnect ||
                    (pnode->GetRefCount() <= 0 && pnode->vRecvMsg.empty() && pnode->nSendSize == 0 && pnode->ssSend.empty()))
                {
                    // remove from vNodes
                    theApp.vNodes().erase(
						remove(	theApp.vNodes().begin(), 
								theApp.vNodes().end(), 
								pnode), 
						theApp.vNodes().end());

                    // release outbound grant (if any)
                    pnode->grantOutbound.Release();

                    // close socket and cleanup
                    pnode->CloseSocketDisconnect();

                    // hold in disconnected pool until all refs are released
                    if (pnode->fNetworkNode || pnode->fInbound)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }
        }
        {
            // Delete disconnected nodes
            list<CEDCNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            BOOST_FOREACH(CEDCNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    {
                        TRY_LOCK(pnode->cs_vSend, lockSend);
                        if (lockSend)
                        {
                            TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                            if (lockRecv)
                            {
                                TRY_LOCK(pnode->cs_inventory, lockInv);
                                if (lockInv)
                                    fDelete = true;
                            }
                        }
                    }
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            }
        }
        if(theApp.vNodes().size() != nPrevNodeCount) 
		{
            nPrevNodeCount = theApp.vNodes().size();
            edcUiInterface.NotifyNumConnectionsChanged(nPrevNodeCount);
        }

        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        fd_set fdsetRecv;
        fd_set fdsetSend;
        fd_set fdsetError;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        SOCKET hSocketMax = 0;
        bool have_fds = false;

        BOOST_FOREACH(const ListenSocket& hListenSocket, vhListenSocket) 
		{
            FD_SET(hListenSocket.socket, &fdsetRecv);
            hSocketMax = max(hSocketMax, hListenSocket.socket);
            have_fds = true;
        }

        {
            LOCK(theApp.vNodesCS());
            BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
            {
                if (pnode->hSocket == INVALID_SOCKET)
                    continue;
                FD_SET(pnode->hSocket, &fdsetError);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                have_fds = true;

                // Implement the following logic:
                // * If there is data to send, select() for sending data. As this only
                //   happens when optimistic write failed, we choose to first drain the
                //   write buffer in this case before receiving more. This avoids
                //   needlessly queueing received data, if the remote peer is not themselves
                //   receiving data. This means properly utilizing TCP flow control signalling.
                // * Otherwise, if there is no (complete) message in the receive buffer,
                //   or there is space left in the buffer, select() for receiving data.
                // * (if neither of the above applies, there is certainly one message
                //   in the receiver buffer ready to be processed).
                // Together, that means that at least one of the following is always possible,
                // so we don't deadlock:
                // * We send some data.
                // * We wait for data to be received (and disconnect after timeout).
                // * We process a message in the buffer (message handler thread).
                {
                    TRY_LOCK(pnode->cs_vSend, lockSend);
                    if (lockSend && !pnode->vSendMsg.empty()) 
					{
                        FD_SET(pnode->hSocket, &fdsetSend);
                        continue;
                    }
                }
                {
                    TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                    if (lockRecv && (
                        pnode->vRecvMsg.empty() || !pnode->vRecvMsg.front().complete() ||
                        pnode->GetTotalRecvSize() <= edcReceiveFloodSize()))
                        FD_SET(pnode->hSocket, &fdsetRecv);
                }
            }
        }

        int nSelect = select(have_fds ? hSocketMax + 1 : 0,
                             &fdsetRecv, &fdsetSend, &fdsetError, &timeout);
        boost::this_thread::interruption_point();

        if (nSelect == SOCKET_ERROR)
        {
            if (have_fds)
            {
                int nErr = WSAGetLastError();
                edcLogPrintf("socket select error %s\n", NetworkErrorString(nErr));
                for (unsigned int i = 0; i <= hSocketMax; i++)
                    FD_SET(i, &fdsetRecv);
            }
            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);
            MilliSleep(timeout.tv_usec/1000);
        }

        //
        // Accept new connections
        //
        BOOST_FOREACH(const ListenSocket& hListenSocket, vhListenSocket)
        {
            if (hListenSocket.socket != INVALID_SOCKET && FD_ISSET(hListenSocket.socket, &fdsetRecv))
            {
                AcceptConnection(hListenSocket);
            }
        }

        //
        // Service each socket
        //
        vector<CEDCNode*> vNodesCopy;
        {
            LOCK(theApp.vNodesCS());
            vNodesCopy = theApp.vNodes();
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
                pnode->AddRef();
        }
        BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
        {
            boost::this_thread::interruption_point();

            //
            // Receive
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetRecv) || FD_ISSET(pnode->hSocket, &fdsetError))
            {
                TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                if (lockRecv)
                {
                    {
                        // typical socket buffer is 8K-64K
                        char pchBuf[0x10000];
                        int nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            if (!pnode->ReceiveMsgBytes(pchBuf, nBytes))
                                pnode->CloseSocketDisconnect();
                            pnode->nLastRecv = GetTime();
                            pnode->nRecvBytes += nBytes;
                            pnode->RecordBytesRecv(nBytes);
                        }
                        else if (nBytes == 0)
                        {
                            // socket closed gracefully
                            if (!pnode->fDisconnect)
                                edcLogPrint("net", "socket closed\n");
                            pnode->CloseSocketDisconnect();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                            {
                                if (!pnode->fDisconnect)
                                    edcLogPrintf("socket recv error %s\n", NetworkErrorString(nErr));
                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }

            //
            // Send
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetSend))
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                    SocketSendData(pnode);
            }

            //
            // Inactivity checking
            //
            int64_t nTime = GetTime();
            if (nTime - pnode->nTimeConnected > 60)
            {
                if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                {
                    edcLogPrint("net", "socket no message in first 60 seconds, %d %d from %d\n", pnode->nLastRecv != 0, pnode->nLastSend != 0, pnode->id);
                    pnode->fDisconnect = true;
                }
                else if (nTime - pnode->nLastSend > TIMEOUT_INTERVAL)
                {
                    edcLogPrintf("socket sending timeout: %is\n", nTime - pnode->nLastSend);
                    pnode->fDisconnect = true;
                }
                else if (nTime - pnode->nLastRecv > (pnode->nVersion > BIP0031_VERSION ? TIMEOUT_INTERVAL : 90*60))
                {
                    edcLogPrintf("socket receive timeout: %is\n", nTime - pnode->nLastRecv);
                    pnode->fDisconnect = true;
                }
                else if (pnode->nPingNonceSent && pnode->nPingUsecStart + TIMEOUT_INTERVAL * 1000000 < GetTimeMicros())
                {
                    edcLogPrintf("ping timeout: %fs\n", 0.000001 * (GetTimeMicros() - pnode->nPingUsecStart));
                    pnode->fDisconnect = true;
                }
            }
        }
        {
            LOCK(theApp.vNodesCS());
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
                pnode->Release();
        }
    }
}

#ifdef USE_UPNP
void ThreadMapPort()
{
    std::string port = strprintf("%u", edcGetListenPort());
    const char * multicastif = 0;
    const char * minissdpdpath = 0;
    struct UPNPDev * devlist = 0;
    char lanaddr[64];

#ifndef UPNPDISCOVER_SUCCESS
    /* miniupnpc 1.5 */
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0);
#elif MINIUPNPC_API_VERSION < 14
    /* miniupnpc 1.6 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, &error);
#else
    /* miniupnpc 1.9.20150730 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, 2, &error);
#endif

    struct UPNPUrls urls;
    struct IGDdatas data;
    int r;

    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (r == 1)
    {
		EDCparams & params = EDCparams::singleton();
        if (params.discover) 
		{
            char externalIPAddress[40];
            r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
            if(r != UPNPCOMMAND_SUCCESS)
                edcLogPrintf("UPnP: GetExternalIPAddress() returned %d\n", r);
            else
            {
                if(externalIPAddress[0])
                {
                    edcLogPrintf("UPnP: ExternalIPAddress = %s\n", externalIPAddress);
                    edcAddLocal(CNetAddr(externalIPAddress), LOCAL_UPNP);
                }
                else
                    edcLogPrintf("UPnP: GetExternalIPAddress failed.\n");
            }
        }

        string strDesc = "Bitcoin " + FormatFullVersion();

        try 
		{
            while (true) 
			{
#ifndef UPNPDISCOVER_SUCCESS
                /* miniupnpc 1.5 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0);
#else
                /* miniupnpc 1.6 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0, "0");
#endif

                if(r!=UPNPCOMMAND_SUCCESS)
                    edcLogPrintf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
                        port, port, lanaddr, r, strupnperror(r));
                else
                    edcLogPrintf("UPnP Port Mapping successful.\n");

                MilliSleep(20*60*1000); // Refresh every 20 minutes
            }
        }
        catch (const boost::thread_interrupted&)
        {
            r = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port.c_str(), "TCP", 0);
            edcLogPrintf("UPNP_DeletePortMapping() returned: %d\n", r);
            freeUPNPDevlist(devlist); devlist = 0;
            FreeUPNPUrls(&urls);
            throw;
        }
    } 
	else 
	{
        edcLogPrintf("No valid UPnP IGDs found\n");
        freeUPNPDevlist(devlist); devlist = 0;
        if (r != 0)
            FreeUPNPUrls(&urls);
    }
}

void edcMapPort(bool fUseUPnP)
{
    static boost::thread* upnp_thread = NULL;

    if (fUseUPnP)
    {
        if (upnp_thread) 
		{
            upnp_thread->interrupt();
            upnp_thread->join();
            delete upnp_thread;
        }
        upnp_thread = new boost::thread(boost::bind(&edcTraceThread<void (*)()>, "upnp", &ThreadMapPort));
    }
    else if (upnp_thread) 
	{
        upnp_thread->interrupt();
        upnp_thread->join();
        delete upnp_thread;
        upnp_thread = NULL;
    }
}

#else
void edcMapPort(bool)
{
    // Intentionally left blank.
}
#endif


void edcThreadDNSAddressSeed()
{
	EDCparams & params = EDCparams::singleton();
	EDCapp & theApp = EDCapp::singleton();

    // goal: only query DNS seeds if address need is acute
    if ((theApp.addrman().size() > 0) && !params.forcednsseed ) 
	{
        MilliSleep(11 * 1000);

        LOCK(theApp.vNodesCS());
        if (theApp.vNodes().size() >= 2) 
		{
            edcLogPrintf("P2P peers available. Skipped DNS seeding.\n");
            return;
        }
    }

    const vector<CDNSSeedData> &vSeeds = edcParams().DNSSeeds();
    int found = 0;

    edcLogPrintf("Loading addresses from DNS seeds (could take a while)\n");

    BOOST_FOREACH(const CDNSSeedData &seed, vSeeds) 
	{
        if (edcHaveNameProxy()) 
		{
            AddOneShot(seed.host);
        } 
		else 
		{
            vector<CNetAddr> vIPs;
            vector<CAddress> vAdd;
            if (LookupHost(seed.host.c_str(), vIPs, 0, true))
            {
                BOOST_FOREACH(const CNetAddr& ip, vIPs)
                {
                    int nOneDay = 24*3600;
                    CAddress addr = CAddress(CService(ip, edcParams().GetDefaultPort()));
                    addr.nTime = GetTime() - 3*nOneDay - GetRand(4*nOneDay); // use a random age between 3 and 7 days old
                    vAdd.push_back(addr);
                    found++;
                }
            }
            // TODO: The seed name resolve may fail, yielding an IP of [::], 
			// which results in theApp.addrman() assigning the same source to 
			// results from different seeds. This should switch to a hard-coded
			// stable dummy IP for each seed name, so that the
            // resolve is not required at all.
            if (!vIPs.empty()) 
			{
                CService seedSource;
                Lookup(seed.name.c_str(), seedSource, 0, true);
                theApp.addrman().Add(vAdd, seedSource);
            }
        }
    }

    edcLogPrintf("%d addresses found from DNS seeds\n", found);
}

void edcDumpAddresses()
{
	EDCapp & theApp = EDCapp::singleton();

    int64_t nStart = GetTimeMillis();

    CEDCAddrDB adb;
    adb.Write(theApp.addrman());

    edcLogPrint("net", "Flushed %d addresses to peers.dat  %dms\n",
           theApp.addrman().size(), GetTimeMillis() - nStart);
}

void edcDumpData()
{
    edcDumpAddresses();
    edcDumpBanlist();
}

void static ProcessOneShot()
{
    string strDest;
    {
        LOCK(edccs_vOneShots);
        if (vOneShots.empty())
            return;
        strDest = vOneShots.front();
        vOneShots.pop_front();
    }
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);
    if (grant) 
	{
        if (!edcOpenNetworkConnection(addr, &grant, strDest.c_str(), true))
            AddOneShot(strDest);
    }
}

void edcThreadOpenConnections()
{
	EDCparams & params = EDCparams::singleton();
    // Connect to specific addresses
    if ( params.connect.size() > 0)
    {
        for (int64_t nLoop = 0;; nLoop++)
        {
            ProcessOneShot();
            BOOST_FOREACH(const std::string& strAddr, params.connect)
            {
                CAddress addr;
                edcOpenNetworkConnection(addr, NULL, strAddr.c_str());
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    MilliSleep(500);
                }
            }
            MilliSleep(500);
        }
    }

	EDCapp & theApp = EDCapp::singleton();

    // Initiate network connections
    int64_t nStart = GetTime();
    while (true)
    {
        ProcessOneShot();

        MilliSleep(500);

        CSemaphoreGrant grant(*semOutbound);
        boost::this_thread::interruption_point();

        // Add seed nodes if DNS seeds are all down (an infrastructure attack?).
        if (theApp.addrman().size() == 0 && (GetTime() - nStart > 60)) 
		{
            static bool done = false;
            if (!done) 
			{
                edcLogPrintf("Adding fixed seed nodes as DNS doesn't seem to be available.\n");
                theApp.addrman().Add(convertSeed6(edcParams().FixedSeeds()), CNetAddr("127.0.0.1"));
                done = true;
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4).
        // Do this here so we don't have to critsect theApp.vNodes() inside mapAddresses critsect.
        int nOutbound = 0;
        set<vector<unsigned char> > setConnected;
        {
            LOCK(theApp.vNodesCS());
            BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes()) 
			{
                if (!pnode->fInbound) 
				{
                    setConnected.insert(pnode->addr.GetGroup());
                    nOutbound++;
                }
            }
        }

        int64_t nANow = edcGetAdjustedTime();

        int nTries = 0;
        while (true)
        {
            CAddrInfo addr = theApp.addrman().Select();

            // if we selected an invalid address, restart
            if (!addr.IsValid() || setConnected.count(addr.GetGroup()) || edcIsLocal(addr))
                break;

            // If we didn't find an appropriate destination after trying 100 addresses fetched from theApp.addrman(),
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new theApp.addrman() addresses.
            nTries++;
            if (nTries > 100)
                break;

            if (edcIsLimited(addr))
                continue;

            // only consider very recently tried nodes after 30 failed attempts
            if (nANow - addr.nLastTry < 600 && nTries < 30)
                continue;

            // do not allow non-default ports, unless after 50 invalid addresses selected already
            if (addr.GetPort() != edcParams().GetDefaultPort() && nTries < 50)
                continue;

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid())
            edcOpenNetworkConnection(addrConnect, &grant);
    }
}

void edcThreadOpenAddedConnections()
{
	EDCapp & theApp = EDCapp::singleton();
	EDCparams & params = EDCparams::singleton();
    {
        LOCK(theApp.addedNodesCS());
        theApp.addedNodes() = params.addnode;
    }

    if (edcHaveNameProxy()) 
	{
        while(true) 
		{
            list<string> lAddresses(0);
            {
                LOCK(theApp.addedNodesCS());
                BOOST_FOREACH(const std::string& strAddNode, theApp.addedNodes())
                    lAddresses.push_back(strAddNode);
            }
            BOOST_FOREACH(const std::string& strAddNode, lAddresses) 
			{
                CAddress addr;
                CSemaphoreGrant grant(*semOutbound);
                edcOpenNetworkConnection(addr, &grant, strAddNode.c_str());
                MilliSleep(500);
            }
            MilliSleep(120000); // Retry every 2 minutes
        }
    }

    for (unsigned int i = 0; true; i++)
    {
        list<string> lAddresses(0);
        {
            LOCK(theApp.addedNodesCS());
            BOOST_FOREACH(const std::string& strAddNode, theApp.addedNodes())
                lAddresses.push_back(strAddNode);
        }

        list<vector<CService> > lservAddressesToAdd(0);
        BOOST_FOREACH(const std::string& strAddNode, lAddresses) 
		{
            vector<CService> vservNode(0);
            if(Lookup(strAddNode.c_str(), vservNode, 
			edcParams().GetDefaultPort(), params.dns, 0))
            {
                lservAddressesToAdd.push_back(vservNode);
                {
                    LOCK(edccs_setservAddNodeAddresses);
                    BOOST_FOREACH(const CService& serv, vservNode)
                        edcsetservAddNodeAddresses.insert(serv);
                }
            }
        }
        // Attempt to connect to each IP for each addnode entry until at least 
		// one is successful per addnode entry
        // (keeping in mind that addnode entries can have many IPs if 
		// params.dns)
        {
            LOCK(theApp.vNodesCS());
            BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
                for (list<vector<CService> >::iterator it = lservAddressesToAdd.begin(); it != lservAddressesToAdd.end(); it++)
                    BOOST_FOREACH(const CService& addrNode, *(it))
                        if (pnode->addr == addrNode)
                        {
                            it = lservAddressesToAdd.erase(it);
                            it--;
                            break;
                        }
        }
        BOOST_FOREACH(vector<CService>& vserv, lservAddressesToAdd)
        {
            CSemaphoreGrant grant(*semOutbound);
            edcOpenNetworkConnection(CAddress(vserv[i % vserv.size()]), &grant);
            MilliSleep(500);
        }
        MilliSleep(120000); // Retry every 2 minutes
    }
}

// if successful, this moves the passed grant to the constructed node
bool edcOpenNetworkConnection(
	 const CAddress & addrConnect, 
	CSemaphoreGrant * grantOutbound, 
	     const char * pszDest, 
	             bool fOneShot )
{
    //
    // Initiate outbound network connection
    //
    boost::this_thread::interruption_point();
    if (!pszDest) 
	{
        if (edcIsLocal(addrConnect) ||
            edcFindNode((CNetAddr)addrConnect) || 
			CEDCNode::IsBanned(addrConnect) ||
            edcFindNode(addrConnect.ToStringIPPort()))
            return false;
    } 
	else if (edcFindNode(std::string(pszDest)))
        return false;

    CEDCNode* pnode = edcConnectNode(addrConnect, pszDest);
    boost::this_thread::interruption_point();

    if (!pnode)
        return false;
    if (grantOutbound)
        grantOutbound->MoveTo(pnode->grantOutbound);
    pnode->fNetworkNode = true;
    if (fOneShot)
        pnode->fOneShot = true;

    return true;
}


void edcThreadMessageHandler()
{
	EDCapp & theApp = EDCapp::singleton();
    boost::mutex condition_mutex;
    boost::unique_lock<boost::mutex> lock(condition_mutex);

    while (true)
    {
        vector<CEDCNode*> vNodesCopy;
        {
            LOCK(theApp.vNodesCS());
            vNodesCopy = theApp.vNodes();
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy) 
			{
                pnode->AddRef();
            }
        }

        bool fSleep = true;

        BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
        {
            if (pnode->fDisconnect)
                continue;

            // Receive messages
            {
                TRY_LOCK(pnode->cs_vRecvMsg, lockRecv);
                if (lockRecv)
                {
                    if (!g_signals.ProcessMessages(pnode))
                        pnode->CloseSocketDisconnect();

                    if (pnode->nSendSize < edcSendBufferSize())
                    {
                        if (!pnode->vRecvGetData.empty() || 
						(!pnode->vRecvMsg.empty() && 
							pnode->vRecvMsg[0].complete()))
                        {
                            fSleep = false;
                        }
                    }
                }
            }
            boost::this_thread::interruption_point();

            // Send messages
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                    g_signals.SendMessages(pnode);
            }
            boost::this_thread::interruption_point();
        }

        {
            LOCK(theApp.vNodesCS());
            BOOST_FOREACH(CEDCNode* pnode, vNodesCopy)
                pnode->Release();
        }

        if (fSleep)
            edcmessageHandlerCondition.timed_wait(lock, 
				boost::posix_time::microsec_clock::universal_time() + 
				boost::posix_time::milliseconds(100));
    }
}

bool edcBindListenPort(
	const CService & addrBind, 
			string & strError, 
				bool fWhitelisted)
{
    strError = "";
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        strError = strprintf("Error: Bind address family for %s not supported", addrBind.ToString());
        edcLogPrintf("%s\n", strError);
        return false;
    }

    SOCKET hListenSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %s)", NetworkErrorString(WSAGetLastError()));
        edcLogPrintf("%s\n", strError);
        return false;
    }
    if (!IsSelectableSocket(hListenSocket))
    {
        strError = "Error: Couldn't create a listenable socket for incoming connections";
        edcLogPrintf("%s\n", strError);
        return false;
    }


#ifndef WIN32
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hListenSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
    // Disable Nagle's algorithm
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&nOne, sizeof(int));
#else
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&nOne, sizeof(int));
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&nOne, sizeof(int));
#endif

    // Set to non-blocking, incoming connections will also inherit this
    if (!SetSocketNonBlocking(hListenSocket, true)) 
	{
        strError = strprintf("edcBindListenPort: Setting listening socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));
        edcLogPrintf("%s\n", strError);
        return false;
    }

    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6()) 
	{
#ifdef IPV6_V6ONLY
#ifdef WIN32
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&nOne, sizeof(int));
#else
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&nOne, sizeof(int));
#endif
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (const char*)&nProtLevel, sizeof(int));
#endif
    }

    if (::bind(hListenSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf(_("Unable to bind to %s on this computer. %s is probably already running."), addrBind.ToString(), _(PACKAGE_NAME));
        else
            strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %s)"), addrBind.ToString(), NetworkErrorString(nErr));
        edcLogPrintf("%s\n", strError);
        CloseSocket(hListenSocket);
        return false;
    }
    edcLogPrintf("Bound to %s\n", addrBind.ToString());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf(_("Error: Listening for incoming connections failed (listen returned error %s)"), NetworkErrorString(WSAGetLastError()));
        edcLogPrintf("%s\n", strError);
        CloseSocket(hListenSocket);
        return false;
    }

    vhListenSocket.push_back(ListenSocket(hListenSocket, fWhitelisted));

	EDCparams & params = EDCparams::singleton();
    if (addrBind.IsRoutable() && params.discover && !fWhitelisted)
        edcAddLocal(addrBind, LOCAL_BIND);

    return true;
}

void static Discover(boost::thread_group& threadGroup)
{
	EDCparams & params = EDCparams::singleton();
    if (!params.discover)
        return;

#ifdef WIN32
    // Get local host IP
    char pszHostName[256] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr, 0, true))
        {
            BOOST_FOREACH (const CNetAddr &addr, vaddr)
            {
                if (edcAddLocal(addr, LOCAL_IF))
                    edcLogPrintf("%s: %s - %s\n", __func__, pszHostName, addr.ToString());
            }
        }
    }
#else
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                CNetAddr addr(s4->sin_addr);
                if (edcAddLocal(addr, LOCAL_IF))
                    edcLogPrintf("%s: IPv4 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                CNetAddr addr(s6->sin6_addr);
                if (edcAddLocal(addr, LOCAL_IF))
                    edcLogPrintf("%s: IPv6 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
}

// learn a new local address
bool edcAddLocal(const CService& addr, int nScore)
{
    if (!addr.IsRoutable())
        return false;

	EDCparams & params = EDCparams::singleton();
    if (!params.discover && nScore < LOCAL_MANUAL)
        return false;

    if (IsLimited(addr))
        return false;

    edcLogPrintf("edcAddLocal(%s,%i)\n", addr.ToString(), nScore);

    {
        LOCK(cs_mapLocalHost);
        bool fAlready = mapLocalHost.count(addr) > 0;
        LocalServiceInfo &info = mapLocalHost[addr];
        if (!fAlready || nScore >= info.nScore) {
            info.nScore = nScore + (fAlready ? 1 : 0);
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

bool edcAddLocal(const CNetAddr &addr, int nScore)
{
    return edcAddLocal(CService(addr, GetListenPort()), nScore);
}

void edcStartNode(boost::thread_group& threadGroup, CScheduler& scheduler)
{
	EDCapp & theApp = EDCapp::singleton();

    edcUiInterface.InitMessage(_("Loading addresses..."));
    // Load addresses from peers.dat
    int64_t nStart = GetTimeMillis();
    {
        CEDCAddrDB adb;
        if (adb.Read(theApp.addrman()))
            edcLogPrintf("Loaded %i addresses from peers.dat  %dms\n", theApp.addrman().size(), GetTimeMillis() - nStart);
        else 
		{
            edcLogPrintf("Invalid or missing peers.dat; recreating\n");
            edcDumpAddresses();
        }
    }

    edcUiInterface.InitMessage(_("Loading banlist..."));
    // Load addresses from banlist.dat
    nStart = GetTimeMillis();
    CEDCBanDB bandb;
    banmap_t banmap;
    if (bandb.Read(banmap)) 
	{
        CEDCNode::SetBanned(banmap); // thread save setter
        CEDCNode::SetBannedSetDirty(false); // no need to write down, just read data
        CEDCNode::SweepBanned(); // sweep out unused entries

        edcLogPrint("net", "Loaded %d banned node ips/subnets from banlist.dat  %dms\n",
            banmap.size(), GetTimeMillis() - nStart);
    } 
	else 
	{
        edcLogPrintf("Invalid or missing banlist.dat; recreating\n");
        CEDCNode::SetBannedSetDirty(true); // force write
        edcDumpBanlist();
    }

    edcfAddressesInitialized = true;

    if (semOutbound == NULL) 
	{
        // initialize semaphore
        int nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, theApp.maxConnections() );
        semOutbound = new CSemaphore(nMaxOutbound);
    }

    if (pnodeLocalHost == NULL)
        pnodeLocalHost = new CEDCNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), theApp.localServices() ));

    Discover(threadGroup);

    //
    // Start threads
    //

	EDCparams & params = EDCparams::singleton();
    if (!params.dnsseed)
        edcLogPrintf("DNS seeding disabled\n");
    else
        threadGroup.create_thread(boost::bind(&edcTraceThread<void (*)()>, "dnsseed", &edcThreadDNSAddressSeed));

    // Map ports with UPnP
    edcMapPort(params.upnp);

    // Send and receive from sockets, accept connections
    threadGroup.create_thread(boost::bind(&edcTraceThread<void (*)()>, "net", &edcThreadSocketHandler));

    // Initiate outbound connections from -eb_addnode
    threadGroup.create_thread(boost::bind(&edcTraceThread<void (*)()>, 
		"addcon", &edcThreadOpenAddedConnections));

    // Initiate outbound connections
    threadGroup.create_thread(boost::bind(&edcTraceThread<void (*)()>, "opencon", &edcThreadOpenConnections));

    // Process messages
    threadGroup.create_thread(boost::bind(&edcTraceThread<void (*)()>, "msghand", &edcThreadMessageHandler));

    // Dump network addresses
    scheduler.scheduleEvery(&edcDumpData, DUMP_ADDRESSES_INTERVAL);
}

bool edcStopNode()
{
    edcLogPrintf("edcStopNode()\n");
    edcMapPort(false);
    if (semOutbound)
        for (int i=0; i<MAX_OUTBOUND_CONNECTIONS; i++)
            semOutbound->post();

    if (edcfAddressesInitialized)
    {
        edcDumpData();
        edcfAddressesInitialized = false;
    }

    return true;
}

class CNetCleanup
{
public:
    CNetCleanup() {}

    ~CNetCleanup()
    {
		EDCapp & theApp = EDCapp::singleton();
        // Close sockets
        BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
            if (pnode->hSocket != INVALID_SOCKET)
                CloseSocket(pnode->hSocket);
        BOOST_FOREACH(ListenSocket& hListenSocket, vhListenSocket)
            if (hListenSocket.socket != INVALID_SOCKET)
                if (!CloseSocket(hListenSocket.socket))
                    edcLogPrintf("CloseSocket(hListenSocket) failed with error %s\n", NetworkErrorString(WSAGetLastError()));

        // clean up some globals (to help leak detection)
        BOOST_FOREACH(CEDCNode *pnode, theApp.vNodes())
            delete pnode;
        BOOST_FOREACH(CEDCNode *pnode, vNodesDisconnected)
            delete pnode;
        theApp.vNodes().clear();
        vNodesDisconnected.clear();
        vhListenSocket.clear();
        delete semOutbound;
        semOutbound = NULL;
        delete pnodeLocalHost;
        pnodeLocalHost = NULL;

#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
}
edcinstance_of_cnetcleanup;


void RelayTransaction(const CEDCTransaction& tx, CFeeRate feerate)
{
	EDCapp & theApp = EDCapp::singleton();
    CInv inv(MSG_TX, tx.GetHash());
    {
        LOCK(theApp.mapRelayCS());
        // Expire old relay messages
        while (!relayExpiration.empty() && relayExpiration.front().first < GetTime())
        {
            theApp.mapRelay().erase(relayExpiration.front().second);
            relayExpiration.pop_front();
        }

        theApp.mapRelay().insert(std::make_pair(inv.hash, tx));
        relayExpiration.push_back(std::make_pair(GetTime() + 15 * 60, inv.hash));
    }
    LOCK(theApp.vNodesCS());
    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes())
    {
        pnode->PushInventory(inv);
    }
}

void RelayUserMessage( CUserMessage * um )
{
	EDCapp & theApp = EDCapp::singleton();

	theApp.walletMain()->AddMessage( um->tag(), um->GetHash(), um );

	LOCK(theApp.vNodesCS());
	BOOST_FOREACH(CEDCNode * pnode, theApp.vNodes())
	{
		pnode->PushUserMessage(um);
	}
}

void CEDCNode::RecordBytesRecv(uint64_t bytes)
{
    LOCK(cs_totalBytesRecv);
    nTotalBytesRecv += bytes;
}

void CEDCNode::RecordBytesSent(uint64_t bytes)
{
    LOCK(cs_totalBytesSent);
    nTotalBytesSent += bytes;

    uint64_t now = GetTime();
    if (nMaxOutboundCycleStartTime + nMaxOutboundTimeframe < now)
    {
        // timeframe expired, reset cycle
        nMaxOutboundCycleStartTime = now;
        nMaxOutboundTotalBytesSentInCycle = 0;
    }

    // TODO, exclude whitebind peers
    nMaxOutboundTotalBytesSentInCycle += bytes;
}

void CEDCNode::SetMaxOutboundTarget(uint64_t limit)
{
    LOCK(cs_totalBytesSent);
    uint64_t recommendedMinimum = (nMaxOutboundTimeframe / 600) * EDC_MAX_BLOCK_SIZE;
    nMaxOutboundLimit = limit;

    if (limit > 0 && limit < recommendedMinimum)
        edcLogPrintf("Max outbound target is very small (%s bytes) and will be overshot. Recommended minimum is %s bytes.\n", nMaxOutboundLimit, recommendedMinimum);
}

uint64_t CEDCNode::GetMaxOutboundTarget()
{
    LOCK(cs_totalBytesSent);
    return nMaxOutboundLimit;
}

uint64_t CEDCNode::GetMaxOutboundTimeframe()
{
    LOCK(cs_totalBytesSent);
    return nMaxOutboundTimeframe;
}

uint64_t CEDCNode::GetMaxOutboundTimeLeftInCycle()
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return 0;

    if (nMaxOutboundCycleStartTime == 0)
        return nMaxOutboundTimeframe;

    uint64_t cycleEndTime = nMaxOutboundCycleStartTime + nMaxOutboundTimeframe;
    uint64_t now = GetTime();
    return (cycleEndTime < now) ? 0 : cycleEndTime - GetTime();
}

void CEDCNode::SetMaxOutboundTimeframe(uint64_t timeframe)
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundTimeframe != timeframe)
    {
        // reset measure-cycle in case of changing
        // the timeframe
        nMaxOutboundCycleStartTime = GetTime();
    }
    nMaxOutboundTimeframe = timeframe;
}

bool CEDCNode::OutboundTargetReached(bool historicalBlockServingLimit)
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return false;

    if (historicalBlockServingLimit)
    {
        // keep a large enough buffer to at least relay each block once
        uint64_t timeLeftInCycle = GetMaxOutboundTimeLeftInCycle();
        uint64_t buffer = timeLeftInCycle / 600 * EDC_MAX_BLOCK_SIZE;
        if (buffer >= nMaxOutboundLimit || nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit - buffer)
            return true;
    }
    else if (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit)
        return true;

    return false;
}

uint64_t CEDCNode::GetOutboundTargetBytesLeft()
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
        return 0;

    return (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit) ? 0 : nMaxOutboundLimit - nMaxOutboundTotalBytesSentInCycle;
}

uint64_t CEDCNode::GetTotalBytesRecv()
{
    LOCK(cs_totalBytesRecv);
    return nTotalBytesRecv;
}

uint64_t CEDCNode::GetTotalBytesSent()
{
    LOCK(cs_totalBytesSent);
    return nTotalBytesSent;
}

void CEDCNode::Fuzz(int nChance)
{
    if (!fSuccessfullyConnected) return; // Don't fuzz initial handshake
    if (GetRand(nChance) != 0) return; // Fuzz 1 of every nChance messages

    switch (GetRand(3))
    {
    case 0:
        // xor a random byte with a random value:
        if (!ssSend.empty()) 
		{
            CDataStream::size_type pos = GetRand(ssSend.size());
            ssSend[pos] ^= (unsigned char)(GetRand(256));
        }
        break;
    case 1:
        // delete a random byte:
        if (!ssSend.empty()) 	
		{
            CDataStream::size_type pos = GetRand(ssSend.size());
            ssSend.erase(ssSend.begin()+pos);
        }
        break;
    case 2:
        // insert a random byte at a random position
        {
            CDataStream::size_type pos = GetRand(ssSend.size());
            char ch = (char)GetRand(256);
            ssSend.insert(ssSend.begin()+pos, ch);
        }
        break;
    }
    // Chance of more than one change half the time:
    // (more changes exponentially less likely):
    Fuzz(2);
}

//
// CEDCAddrDB
//

CEDCAddrDB::CEDCAddrDB()
{
    pathAddr = edcGetDataDir() / "peers.dat";
}

bool CEDCAddrDB::Write(const CAddrMan& addr)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string tmpfn = strprintf("peers.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssPeers(SER_DISK, CLIENT_VERSION);
    ssPeers << FLATDATA(edcParams().MessageStart());
    ssPeers << addr;
    uint256 hash = Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = edcGetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return edcError("%s: Failed to open file %s", __func__, pathTmp.string());

    // Write and commit header, data
    try {
        fileout << ssPeers;
    }
    catch (const std::exception& e) {
        return edcError("%s: Serialize or I/O error - %s", __func__, e.what());
    }
    FileCommit(fileout.Get());
    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if (!RenameOver(pathTmp, pathAddr))
        return edcError("%s: Rename-into-place failed", __func__);

    return true;
}

bool CEDCAddrDB::Read(CAddrMan& addr)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathAddr.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return edcError("%s: Failed to open file %s", __func__, pathAddr.string());

    // use file size to size memory buffer
    uint64_t fileSize = boost::filesystem::file_size(pathAddr);
    uint64_t dataSize = 0;
    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
        dataSize = fileSize - sizeof(uint256);
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try 
	{
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e) 
	{
        return edcError("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();

    CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssPeers.begin(), ssPeers.end());
    if (hashIn != hashTmp)
        return edcError("%s: Checksum mismatch, data corrupted", __func__);

    unsigned char pchMsgTmp[4];
    try 
	{
        // de-serialize file header (network specific magic number) and ..
        ssPeers >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, edcParams().MessageStart(), sizeof(pchMsgTmp)))
            return edcError("%s: Invalid network magic number", __func__);

        // de-serialize address data into one CAddrMan object
        ssPeers >> addr;
    }
    catch (const std::exception& e) 
	{
        return edcError("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    return true;
}

unsigned int edcReceiveFloodSize() 
{ 
	EDCparams & params = EDCparams::singleton();
	return 1000*params.maxreceivebuffer; 
}
unsigned int edcSendBufferSize() 
{ 
	EDCparams & params = EDCparams::singleton();
	return 1000*params.maxsendbuffer; 
}

CEDCNode::CEDCNode(
			     SOCKET hSocketIn, 
	   const CAddress & addrIn, 
	const std::string & addrNameIn, 
				   bool fInboundIn) :
    ssSend(SER_NETWORK, INIT_PROTO_VERSION),
    addrKnown(5000, 0.001),
    filterInventoryKnown(50000, 0.000001)
{
    nServices = 0;
    hSocket = hSocketIn;
    nRecvVersion = INIT_PROTO_VERSION;
    nLastSend = 0;
    nLastRecv = 0;
    nSendBytes = 0;
    nRecvBytes = 0;
    nTimeConnected = GetTime();
    nTimeOffset = 0;
    addr = addrIn;
    addrName = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;
    nVersion = 0;
    strSubVer = "";
    fWhitelisted = false;
    fOneShot = false;
    fClient = false; // set by version message
    fInbound = fInboundIn;
    fNetworkNode = false;
    fSuccessfullyConnected = false;
    fDisconnect = false;
    nRefCount = 0;
    nSendSize = 0;
    nSendOffset = 0;
    hashContinue = uint256();
    nStartingHeight = -1;
    filterInventoryKnown.reset();
    fSendMempool = false;
    fGetAddr = false;
    nNextLocalAddrSend = 0;
    nNextAddrSend = 0;
    nNextInvSend = 0;
    fRelayTxes = false;
    fSentAddr = false;
    pfilter = new CEDCBloomFilter();
    nPingNonceSent = 0;
    nPingUsecStart = 0;
    nPingUsecTime = 0;
    fPingQueued = false;
    nMinPingUsecTime = std::numeric_limits<int64_t>::max();
    minFeeFilter = 0;
    lastSentFeeFilter = 0;
    nextSendTimeFeeFilter = 0;

    BOOST_FOREACH(const std::string &msg, edcgetAllNetMessageTypes())
        mapRecvBytesPerMsgCmd[msg] = 0;
    mapRecvBytesPerMsgCmd[NET_MESSAGE_COMMAND_OTHER] = 0;

    {
		static NodeId lastNodeId = 0;
		static CCriticalSection lastNodeIdCS;

        LOCK(lastNodeIdCS);
        id = lastNodeId++;
    }

	EDCparams & params = EDCparams::singleton();
    if (params.logips)
        edcLogPrint("net", "Added connection to %s peer=%d\n", addrName, id);
    else
        edcLogPrint("net", "Added connection peer=%d\n", id);

    // Be shy and don't send version until we hear
    if (hSocket != INVALID_SOCKET && !fInbound)
        PushVersion();

    edcGetNodeSignals().InitializeNode(GetId(), this);
}

CEDCNode::~CEDCNode()
{
    CloseSocket(hSocket);

    if (pfilter)
        delete pfilter;

    edcGetNodeSignals().FinalizeNode(GetId());
}

void CEDCNode::AskFor(const CInv& inv)
{
	EDCapp & theApp = EDCapp::singleton();

    if (mapAskFor.size() > MAPASKFOR_MAX_SZ || setAskFor.size() > SETASKFOR_MAX_SZ)
        return;
    // a peer may not have multiple non-responded queue positions for a single inv item
    if (!setAskFor.insert(inv.hash).second)
        return;

    // We're using mapAskFor as a priority queue,
    // the key is the earliest time the request can be sent
    int64_t nRequestTime;
    limitedmap<uint256, int64_t>::const_iterator it = 
		theApp.mapAlreadyAskedFor().find(inv.hash);

    if (it != theApp.mapAlreadyAskedFor().end())
        nRequestTime = it->second;
    else
        nRequestTime = 0;
    edcLogPrint("net", "askfor %s  %d (%s) peer=%d\n", inv.ToString(), nRequestTime, DateTimeStrFormat("%H:%M:%S", nRequestTime/1000000), id);

    // Make sure not to reuse time indexes to keep things in the same order
    int64_t nNow = GetTimeMicros() - 1000000;
    static int64_t nLastTime;
    ++nLastTime;
    nNow = std::max(nNow, nLastTime);
    nLastTime = nNow;

    // Each retry is 2 minutes after the last
    nRequestTime = std::max(nRequestTime + 2 * 60 * 1000000, nNow);
    if (it != theApp.mapAlreadyAskedFor().end())
        theApp.mapAlreadyAskedFor().update(it, nRequestTime);
    else
        theApp.mapAlreadyAskedFor().insert(std::make_pair(inv.hash, nRequestTime));
    mapAskFor.insert(std::make_pair(nRequestTime, inv));
}

void CEDCNode::BeginMessage(const char* pszCommand) EXCLUSIVE_LOCK_FUNCTION(cs_vSend)
{
    ENTER_CRITICAL_SECTION(cs_vSend);
    assert(ssSend.size() == 0);
    ssSend << CMessageHeader(edcParams().MessageStart(), pszCommand, 0);
    edcLogPrint("net", "sending: %s ", SanitizeString(pszCommand));
}

void CEDCNode::AbortMessage() UNLOCK_FUNCTION(cs_vSend)
{
    ssSend.clear();

    LEAVE_CRITICAL_SECTION(cs_vSend);

    edcLogPrint("net", "(aborted)\n");
}

void CEDCNode::EndMessage(const char* pszCommand) UNLOCK_FUNCTION(cs_vSend)
{
    // The -*messagestest options are intentionally not documented in the help message,
    // since they are only used during development to debug the networking code and are
    // not intended for end-users.
	EDCparams & params = EDCparams::singleton();
    if ( params.dropmessagestest && GetRand(params.dropmessagestest) == 0)
    {
        edcLogPrint("net", "dropmessages DROPPING SEND MESSAGE\n");
        AbortMessage();
        return;
    }
    if (params.fuzzmessagetest > 0 )
        Fuzz(params.fuzzmessagetest);

    if (ssSend.size() == 0)
    {
        LEAVE_CRITICAL_SECTION(cs_vSend);
        return;
    }
    // Set the size
    unsigned int nSize = ssSend.size() - CMessageHeader::HEADER_SIZE;
    WriteLE32((uint8_t*)&ssSend[CMessageHeader::MESSAGE_SIZE_OFFSET], nSize);

    //log total amount of bytes per command
    mapSendBytesPerMsgCmd[std::string(pszCommand)] += nSize + CMessageHeader::HEADER_SIZE;

    // Set the checksum
    uint256 hash = Hash(ssSend.begin() + CMessageHeader::HEADER_SIZE, ssSend.end());
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    assert(ssSend.size () >= CMessageHeader::CHECKSUM_OFFSET + sizeof(nChecksum));
    memcpy((char*)&ssSend[CMessageHeader::CHECKSUM_OFFSET], &nChecksum, sizeof(nChecksum));

    edcLogPrint("net", "(%d bytes) peer=%d\n", nSize, id);

    std::deque<CSerializeData>::iterator it = vSendMsg.insert(vSendMsg.end(), CSerializeData());
    ssSend.GetAndClear(*it);
    nSendSize += (*it).size();

    // If write queue empty, attempt "optimistic write"
    if (it == vSendMsg.begin())
        SocketSendData(this);

    LEAVE_CRITICAL_SECTION(cs_vSend);
}


//
// CEDCBanDB
//

CEDCBanDB::CEDCBanDB()
{
    pathBanlist = edcGetDataDir() / "banlist.dat";
}

bool CEDCBanDB::Write(const banmap_t& banSet)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string tmpfn = strprintf("banlist.dat.%04x", randv);

    // serialize banlist, checksum data up to that point, then append csum
    CDataStream ssBanlist(SER_DISK, CLIENT_VERSION);
    ssBanlist << FLATDATA(edcParams().MessageStart());
    ssBanlist << banSet;
    uint256 hash = Hash(ssBanlist.begin(), ssBanlist.end());
    ssBanlist << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = edcGetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return edcError("%s: Failed to open file %s", __func__, pathTmp.string());

    // Write and commit header, data
    try 
	{
        fileout << ssBanlist;
    }
    catch (const std::exception& e) 
	{
        return edcError("%s: Serialize or I/O error - %s", __func__, e.what());
    }

    FileCommit(fileout.Get());
    fileout.fclose();

    // replace existing banlist.dat, if any, with new banlist.dat.XXXX
    if (!RenameOver(pathTmp, pathBanlist))
        return edcError("%s: Rename-into-place failed", __func__);

    return true;
}

bool CEDCBanDB::Read(banmap_t& banSet)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathBanlist.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return edcError("%s: Failed to open file %s", __func__, pathBanlist.string());

    // use file size to size memory buffer
    uint64_t fileSize = boost::filesystem::file_size(pathBanlist);
    uint64_t dataSize = 0;

    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
        dataSize = fileSize - sizeof(uint256);
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try 
	{
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e
	) {
        return edcError("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();

    CDataStream ssBanlist(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssBanlist.begin(), ssBanlist.end());
    if (hashIn != hashTmp)
        return edcError("%s: Checksum mismatch, data corrupted", __func__);

    unsigned char pchMsgTmp[4];
    try 
	{
        // de-serialize file header (network specific magic number) and ..
        ssBanlist >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, edcParams().MessageStart(), sizeof(pchMsgTmp)))
            return edcError("%s: Invalid network magic number", __func__);

        // de-serialize address data into one CAddrMan object
        ssBanlist >> banSet;
    }
    catch (const std::exception& e) 
	{
        return edcError("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    return true;
}

void edcDumpBanlist()
{
    CEDCNode::SweepBanned(); // clean unused entries (if bantime has expired)

    if (!CEDCNode::BannedSetIsDirty())
        return;

    int64_t nStart = GetTimeMillis();

    CEDCBanDB bandb;
    banmap_t banmap;
    CEDCNode::SetBannedSetDirty(false);
    CEDCNode::GetBanned(banmap);
    if (!bandb.Write(banmap))
        CEDCNode::SetBannedSetDirty(true);

    edcLogPrint("net", "Flushed %d banned node ips/subnets to banlist.dat  %dms\n",
        banmap.size(), GetTimeMillis() - nStart);
}

int64_t edcPoissonNextSend(int64_t nNow, int average_interval_seconds) 
{
    return nNow + (int64_t)(log1p(GetRand(1ULL << 48) * 
		-0.0000000000000035527136788 /* -1/2^48 */) * 
		average_interval_seconds * -1000000.0 + 0.5);
}
