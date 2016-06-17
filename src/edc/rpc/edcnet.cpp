// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edc/rpc/edcserver.h"

#include "edc/edcchainparams.h"
#include "clientversion.h"
#include "edc/edcmain.h"
#include "edc/edcnet.h"
#include "netbase.h"
#include "protocol.h"
#include "sync.h"
#include "timedata.h"
#include "ui_interface.h"
#include "edc/edcutil.h"
#include "utilstrencodings.h"
#include "version.h"
#include "edc/edcapp.h"


#include <boost/foreach.hpp>

#include <univalue.h>

using namespace std;

UniValue edcgetconnectioncount(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getconnectioncount\n"
            "\nReturns the number of connections to other nodes.\n"
            "\nResult:\n"
            "n          (numeric) The connection count\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getconnectioncount", "")
            + HelpExampleRpc("eb_getconnectioncount", "")
        );

    LOCK2(cs_main, theApp.vNodesCS());

    return (int)theApp.vNodes().size();
}

UniValue edcping(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_ping\n"
            "\nRequests that a ping be sent to all other nodes, to measure ping time.\n"
            "Results provided in eb_getpeerinfo, pingtime and pingwait fields are decimal seconds.\n"
            "Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_ping", "")
            + HelpExampleRpc("eb_ping", "")
        );

    // Request that each node send a ping during next message processing pass
    LOCK2(cs_main, theApp.vNodesCS());

    BOOST_FOREACH(CEDCNode* pNode, theApp.vNodes()) {
        pNode->fPingQueued = true;
    }

    return NullUniValue;
}

static void CopyNodeStats(std::vector<CNodeStats>& vstats)
{
	EDCapp & theApp = EDCapp::singleton();
    vstats.clear();

    LOCK(theApp.vNodesCS());
    vstats.reserve(theApp.vNodes().size());
    BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes()) {
        CNodeStats stats;
        pnode->copyStats(stats);
        vstats.push_back(stats);
    }
}

UniValue edcgetpeerinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getpeerinfo\n"
            "\nReturns data about each connected network node as a json array of objects.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"id\": n,                   (numeric) Peer index\n"
            "    \"addr\":\"host:port\",      (string) The ip address and port of the peer\n"
            "    \"addrlocal\":\"ip:port\",   (string) local address\n"
            "    \"services\":\"xxxxxxxxxxxxxxxx\",   (string) The services offered\n"
            "    \"relaytxes\":true|false,    (boolean) Whether peer has asked us to relay transactions to it\n"
            "    \"lastsend\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last send\n"
            "    \"lastrecv\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
            "    \"bytessent\": n,            (numeric) The total bytes sent\n"
            "    \"bytesrecv\": n,            (numeric) The total bytes received\n"
            "    \"conntime\": ttt,           (numeric) The connection time in seconds since epoch (Jan 1 1970 GMT)\n"
            "    \"timeoffset\": ttt,         (numeric) The time offset in seconds\n"
            "    \"pingtime\": n,             (numeric) ping time (if available)\n"
            "    \"minping\": n,              (numeric) minimum observed ping time (if any at all)\n"
            "    \"pingwait\": n,             (numeric) ping wait (if non-zero)\n"
            "    \"version\": v,              (numeric) The peer version, such as 7001\n"
            "    \"subver\": \"/Satoshi:0.8.5/\",  (string) The string version\n"
            "    \"inbound\": true|false,     (boolean) Inbound (true) or Outbound (false)\n"
            "    \"startingheight\": n,       (numeric) The starting height (block) of the peer\n"
            "    \"banscore\": n,             (numeric) The ban score\n"
            "    \"synced_headers\": n,       (numeric) The last header we have in common with this peer\n"
            "    \"synced_blocks\": n,        (numeric) The last block we have in common with this peer\n"
            "    \"inflight\": [\n"
            "       n,                        (numeric) The heights of blocks we're currently asking from this peer\n"
            "       ...\n"
            "    ]\n"
            "    \"bytessent_per_msg\": {\n"
            "       \"addr\": n,             (numeric) The total bytes sent aggregated by message type\n"
            "       ...\n"
            "    }\n"
            "    \"bytesrecv_per_msg\": {\n"
            "       \"addr\": n,             (numeric) The total bytes received aggregated by message type\n"
            "       ...\n"
            "    }\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getpeerinfo", "")
            + HelpExampleRpc("eb_getpeerinfo", "")
        );

    LOCK(cs_main);

    vector<CNodeStats> vstats;
    CopyNodeStats(vstats);

    UniValue ret(UniValue::VARR);

    BOOST_FOREACH(const CNodeStats& stats, vstats) {
        UniValue obj(UniValue::VOBJ);
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        obj.push_back(Pair("id", stats.nodeid));
        obj.push_back(Pair("addr", stats.addrName));
        if (!(stats.addrLocal.empty()))
            obj.push_back(Pair("addrlocal", stats.addrLocal));
        obj.push_back(Pair("services", strprintf("%016x", stats.nServices)));
        obj.push_back(Pair("relaytxes", stats.fRelayTxes));
        obj.push_back(Pair("lastsend", stats.nLastSend));
        obj.push_back(Pair("lastrecv", stats.nLastRecv));
        obj.push_back(Pair("bytessent", stats.nSendBytes));
        obj.push_back(Pair("bytesrecv", stats.nRecvBytes));
        obj.push_back(Pair("conntime", stats.nTimeConnected));
        obj.push_back(Pair("timeoffset", stats.nTimeOffset));
        if (stats.dPingTime > 0.0)
            obj.push_back(Pair("pingtime", stats.dPingTime));
        if (stats.dPingMin < std::numeric_limits<int64_t>::max()/1e6)
            obj.push_back(Pair("minping", stats.dPingMin));
        if (stats.dPingWait > 0.0)
            obj.push_back(Pair("pingwait", stats.dPingWait));
        obj.push_back(Pair("version", stats.nVersion));
        // Use the sanitized form of subver here, to avoid tricksy remote peers from
        // corrupting or modifiying the JSON output by putting special characters in
        // their ver message.
        obj.push_back(Pair("subver", stats.cleanSubVer));
        obj.push_back(Pair("inbound", stats.fInbound));
        obj.push_back(Pair("startingheight", stats.nStartingHeight));
        if (fStateStats) {
            obj.push_back(Pair("banscore", statestats.nMisbehavior));
            obj.push_back(Pair("synced_headers", statestats.nSyncHeight));
            obj.push_back(Pair("synced_blocks", statestats.nCommonHeight));
            UniValue heights(UniValue::VARR);
            BOOST_FOREACH(int height, statestats.vHeightInFlight) {
                heights.push_back(height);
            }
            obj.push_back(Pair("inflight", heights));
        }
        obj.push_back(Pair("whitelisted", stats.fWhitelisted));

        UniValue sendPerMsgCmd(UniValue::VOBJ);
        BOOST_FOREACH(const mapMsgCmdSize::value_type &i, stats.mapSendBytesPerMsgCmd) {
            if (i.second > 0)
                sendPerMsgCmd.push_back(Pair(i.first, i.second));
        }
        obj.push_back(Pair("bytessent_per_msg", sendPerMsgCmd));

        UniValue recvPerMsgCmd(UniValue::VOBJ);
        BOOST_FOREACH(const mapMsgCmdSize::value_type &i, stats.mapRecvBytesPerMsgCmd) {
            if (i.second > 0)
                recvPerMsgCmd.push_back(Pair(i.first, i.second));
        }
        obj.push_back(Pair("bytesrecv_per_msg", recvPerMsgCmd));

        ret.push_back(obj);
    }

    return ret;
}

UniValue edcaddnode(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    string strCommand;
    if (params.size() == 2)
        strCommand = params[1].get_str();
    if (fHelp || params.size() != 2 ||
        (strCommand != "onetry" && strCommand != "add" && strCommand != "remove"))
        throw runtime_error(
            "eb_addnode \"node\" \"add|remove|onetry\"\n"
            "\nAttempts add or remove a node from the addnode list.\n"
            "Or try a connection to a node once.\n"
            "\nArguments:\n"
            "1. \"node\"     (string, required) The node (see eb_getpeerinfo for nodes)\n"
            "2. \"command\"  (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_addnode", "\"192.168.0.6:8333\" \"onetry\"")
            + HelpExampleRpc("eb_addnode", "\"192.168.0.6:8333\", \"onetry\"")
        );

    string strNode = params[0].get_str();

    if (strCommand == "onetry")
    {
        CAddress addr;
        OpenNetworkConnection(addr, NULL, strNode.c_str());
        return NullUniValue;
    }

    LOCK(theApp.addedNodesCS());
    vector<string>::iterator it = theApp.addedNodes().begin();
    for(; it != theApp.addedNodes().end(); it++)
        if (strNode == *it)
            break;

    if (strCommand == "add")
    {
        if (it != theApp.addedNodes().end())
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added");
        theApp.addedNodes().push_back(strNode);
    }
    else if(strCommand == "remove")
    {
        if (it == theApp.addedNodes().end())
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
        theApp.addedNodes().erase(it);
    }

    return NullUniValue;
}

UniValue edcdisconnectnode(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "eb_disconnectnode \"node\" \n"
            "\nImmediately disconnects from the specified node.\n"
            "\nArguments:\n"
            "1. \"node\"     (string, required) The node (see eb_getpeerinfo for nodes)\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_disconnectnode", "\"192.168.0.6:8333\"")
            + HelpExampleRpc("eb_disconnectnode", "\"192.168.0.6:8333\"")
        );

    CEDCNode* pNode = edcFindNode(params[0].get_str());
    if (pNode == NULL)
        throw JSONRPCError(RPC_CLIENT_NODE_NOT_CONNECTED, "Node not found in connected nodes");

    pNode->fDisconnect = true;

    return NullUniValue;
}

UniValue edcgetaddednodeinfo(const UniValue& params, bool fHelp)
{
	EDCapp & theApp = EDCapp::singleton();

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "eb_getaddednodeinfo dns ( \"node\" )\n"
            "\nReturns information about the given added node, or all added nodes\n"
            "(note that onetry addnodes are not listed here)\n"
            "If dns is false, only a list of added nodes will be provided,\n"
            "otherwise connected information will also be available.\n"
            "\nArguments:\n"
            "1. dns        (boolean, required) If false, only a list of added nodes will be provided, otherwise connected information will also be available.\n"
            "2. \"node\"   (string, optional) If provided, return information about this specific node, otherwise all nodes are returned.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"addednode\" : \"192.168.0.201\",   (string) The node ip address\n"
            "    \"connected\" : true|false,          (boolean) If connected\n"
            "    \"addresses\" : [\n"
            "       {\n"
            "         \"address\" : \"192.168.0.201:8333\",  (string) The bitcoin server host and port\n"
            "         \"connected\" : \"outbound\"           (string) connection, inbound or outbound\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getaddednodeinfo", "true")
            + HelpExampleCli("eb_getaddednodeinfo", "true \"192.168.0.201\"")
            + HelpExampleRpc("eb_getaddednodeinfo", "true, \"192.168.0.201\"")
        );

    bool fDns = params[0].get_bool();

    list<string> laddedNodes(0);
    if (params.size() == 1)
    {
        LOCK(theApp.addedNodesCS());
        BOOST_FOREACH(const std::string& strAddNode, theApp.addedNodes())
            laddedNodes.push_back(strAddNode);
    }
    else
    {
        string strNode = params[1].get_str();
        LOCK(theApp.addedNodesCS());
        BOOST_FOREACH(const std::string& strAddNode, theApp.addedNodes()) {
            if (strAddNode == strNode)
            {
                laddedNodes.push_back(strAddNode);
                break;
            }
        }
        if (laddedNodes.size() == 0)
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
    }

    UniValue ret(UniValue::VARR);
    if (!fDns)
    {
        BOOST_FOREACH (const std::string& strAddNode, laddedNodes) {
            UniValue obj(UniValue::VOBJ);
            obj.push_back(Pair("addednode", strAddNode));
            ret.push_back(obj);
        }
        return ret;
    }

    list<pair<string, vector<CService> > > laddedAddreses(0);
    BOOST_FOREACH(const std::string& strAddNode, laddedNodes) {
        vector<CService> vservNode(0);
        if(Lookup(strAddNode.c_str(), vservNode, edcParams().GetDefaultPort(), fNameLookup, 0))
            laddedAddreses.push_back(make_pair(strAddNode, vservNode));
        else
        {
            UniValue obj(UniValue::VOBJ);
            obj.push_back(Pair("addednode", strAddNode));
            obj.push_back(Pair("connected", false));
            UniValue addresses(UniValue::VARR);
            obj.push_back(Pair("addresses", addresses));
            ret.push_back(obj);
        }
    }

    LOCK(theApp.vNodesCS());
    for (list<pair<string, vector<CService> > >::iterator it = laddedAddreses.begin(); it != laddedAddreses.end(); it++)
    {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("addednode", it->first));

        UniValue addresses(UniValue::VARR);
        bool fConnected = false;
        BOOST_FOREACH(const CService& addrNode, it->second) {
            bool fFound = false;
            UniValue node(UniValue::VOBJ);
            node.push_back(Pair("address", addrNode.ToString()));
            BOOST_FOREACH(CEDCNode* pnode, theApp.vNodes()) 
			{
                if (pnode->addr == addrNode)
                {
                    fFound = true;
                    fConnected = true;
                    node.push_back(Pair("connected", pnode->fInbound ? "inbound" : "outbound"));
                    break;
                }
            }
            if (!fFound)
                node.push_back(Pair("connected", "false"));
            addresses.push_back(node);
        }
        obj.push_back(Pair("connected", fConnected));
        obj.push_back(Pair("addresses", addresses));
        ret.push_back(obj);
    }

    return ret;
}

UniValue edcgetnettotals(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "eb_getnettotals\n"
            "\nReturns information about network traffic, including bytes in, bytes out,\n"
            "and current time.\n"
            "\nResult:\n"
            "{\n"
            "  \"totalbytesrecv\": n,   (numeric) Total bytes received\n"
            "  \"totalbytessent\": n,   (numeric) Total bytes sent\n"
            "  \"timemillis\": t,       (numeric) Total cpu time\n"
            "  \"uploadtarget\":\n"
            "  {\n"
            "    \"timeframe\": n,                         (numeric) Length of the measuring timeframe in seconds\n"
            "    \"target\": n,                            (numeric) Target in bytes\n"
            "    \"target_reached\": true|false,           (boolean) True if target is reached\n"
            "    \"serve_historical_blocks\": true|false,  (boolean) True if serving historical blocks\n"
            "    \"bytes_left_in_cycle\": t,               (numeric) Bytes left in current time cycle\n"
            "    \"time_left_in_cycle\": t                 (numeric) Seconds left in current time cycle\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getnettotals", "")
            + HelpExampleRpc("eb_getnettotals", "")
       );

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("totalbytesrecv", CEDCNode::GetTotalBytesRecv()));
    obj.push_back(Pair("totalbytessent", CEDCNode::GetTotalBytesSent()));
    obj.push_back(Pair("timemillis", GetTimeMillis()));

    UniValue outboundLimit(UniValue::VOBJ);
    outboundLimit.push_back(Pair("timeframe", CEDCNode::GetMaxOutboundTimeframe()));
    outboundLimit.push_back(Pair("target", CEDCNode::GetMaxOutboundTarget()));
    outboundLimit.push_back(Pair("target_reached", CEDCNode::OutboundTargetReached(false)));
    outboundLimit.push_back(Pair("serve_historical_blocks", !CEDCNode::OutboundTargetReached(true)));
    outboundLimit.push_back(Pair("bytes_left_in_cycle", CEDCNode::GetOutboundTargetBytesLeft()));
    outboundLimit.push_back(Pair("time_left_in_cycle", CEDCNode::GetMaxOutboundTimeLeftInCycle()));
    obj.push_back(Pair("uploadtarget", outboundLimit));
    return obj;
}

static UniValue GetNetworksInfo()
{
    UniValue networks(UniValue::VARR);
    for(int n=0; n<NET_MAX; ++n)
    {
        enum Network network = static_cast<enum Network>(n);
        if(network == NET_UNROUTABLE)
            continue;
        proxyType proxy;
        UniValue obj(UniValue::VOBJ);
        GetProxy(network, proxy);
        obj.push_back(Pair("name", GetNetworkName(network)));
        obj.push_back(Pair("limited", IsLimited(network)));
        obj.push_back(Pair("reachable", IsReachable(network)));
        obj.push_back(Pair("proxy", proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string()));
        obj.push_back(Pair("proxy_randomize_credentials", proxy.randomize_credentials));
        networks.push_back(obj);
    }
    return networks;
}

extern int64_t edcGetTimeOffset();

UniValue edcgetnetworkinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "eb_getnetworkinfo\n"
            "Returns an object containing various state info regarding P2P networking.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,                      (numeric) the server version\n"
            "  \"subversion\": \"/Satoshi:x.x.x/\",     (string) the server subversion string\n"
            "  \"protocolversion\": xxxxx,              (numeric) the protocol version\n"
            "  \"localservices\": \"xxxxxxxxxxxxxxxx\", (string) the services we offer to the network\n"
            "  \"timeoffset\": xxxxx,                   (numeric) the time offset\n"
            "  \"connections\": xxxxx,                  (numeric) the number of connections\n"
            "  \"networks\": [                          (array) information per network\n"
            "  {\n"
            "    \"name\": \"xxx\",                     (string) network (ipv4, ipv6 or onion)\n"
            "    \"limited\": true|false,               (boolean) is the network limited using -onlynet?\n"
            "    \"reachable\": true|false,             (boolean) is the network reachable?\n"
            "    \"proxy\": \"host:port\"               (string) the proxy that is used for this network, or empty if none\n"
            "  }\n"
            "  ,...\n"
            "  ],\n"
            "  \"relayfee\": x.xxxxxxxx,                (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"localaddresses\": [                    (array) list of local addresses\n"
            "  {\n"
            "    \"address\": \"xxxx\",                 (string) network address\n"
            "    \"port\": xxx,                         (numeric) network port\n"
            "    \"score\": xxx                         (numeric) relative score\n"
            "  }\n"
            "  ,...\n"
            "  ]\n"
            "  \"warnings\": \"...\"                    (string) any network warnings (such as alert messages) \n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("eb_getnetworkinfo", "")
            + HelpExampleRpc("eb_getnetworkinfo", "")
        );

    LOCK(cs_main);

	EDCapp & theApp = EDCapp::singleton();

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version",       CLIENT_VERSION));
    obj.push_back(Pair("subversion",    theApp.strSubVersion() ));
    obj.push_back(Pair("protocolversion",PROTOCOL_VERSION));
    obj.push_back(Pair("localservices",       strprintf("%016x", theApp.localServices())));
    obj.push_back(Pair("timeoffset",    edcGetTimeOffset()));
    obj.push_back(Pair("connections",   (int)theApp.vNodes().size()));
    obj.push_back(Pair("networks",      GetNetworksInfo()));
    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    UniValue localAddresses(UniValue::VARR);
    {
        LOCK(theApp.mapLocalHostCS());
        BOOST_FOREACH(const PAIRTYPE(CNetAddr, LocalServiceInfo) &item, theApp.mapLocalHost())
        {
            UniValue rec(UniValue::VOBJ);
            rec.push_back(Pair("address", item.first.ToString()));
            rec.push_back(Pair("port", item.second.nPort));
            rec.push_back(Pair("score", item.second.nScore));
            localAddresses.push_back(rec);
        }
    }
    obj.push_back(Pair("localaddresses", localAddresses));
    obj.push_back(Pair("warnings",       edcGetWarnings("statusbar")));
    return obj;
}

UniValue edcsetban(const UniValue& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 2)
        strCommand = params[1].get_str();
    if (fHelp || params.size() < 2 ||
        (strCommand != "add" && strCommand != "remove"))
        throw runtime_error(
                            "eb_setban \"ip(/netmask)\" \"add|remove\" (bantime) (absolute)\n"
                            "\nAttempts add or remove a IP/Subnet from the banned list.\n"
                            "\nArguments:\n"
                            "1. \"ip(/netmask)\" (string, required) The IP/Subnet (see eb_getpeerinfo for nodes ip) with a optional netmask (default is /32 = single ip)\n"
                            "2. \"command\"      (string, required) 'add' to add a IP/Subnet to the list, 'remove' to remove a IP/Subnet from the list\n"
                            "3. \"bantime\"      (numeric, optional) time in seconds how long (or until when if [absolute] is set) the ip is banned (0 or empty means using the default time of 24h which can also be overwritten by the -bantime startup argument)\n"
                            "4. \"absolute\"     (boolean, optional) If set, the bantime must be a absolute timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("eb_setban", "\"192.168.0.6\" \"add\" 86400")
                            + HelpExampleCli("eb_setban", "\"192.168.0.0/24\" \"add\"")
                            + HelpExampleRpc("eb_setban", "\"192.168.0.6\", \"add\" 86400")
                            );

    CSubNet subNet;
    CNetAddr netAddr;
    bool isSubnet = false;

    if (params[0].get_str().find("/") != string::npos)
        isSubnet = true;

    if (!isSubnet)
        netAddr = CNetAddr(params[0].get_str());
    else
        subNet = CSubNet(params[0].get_str());

    if (! (isSubnet ? subNet.IsValid() : netAddr.IsValid()) )
        throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Invalid IP/Subnet");

    if (strCommand == "add")
    {
        if (isSubnet ? CEDCNode::IsBanned(subNet) : CEDCNode::IsBanned(netAddr))
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: IP/Subnet already banned");

        int64_t banTime = 0; //use standard bantime if not specified
        if (params.size() >= 3 && !params[2].isNull())
            banTime = params[2].get_int64();

        bool absolute = false;
        if (params.size() == 4 && params[3].isTrue())
            absolute = true;

        isSubnet ? CEDCNode::Ban(subNet, BanReasonManuallyAdded, banTime, absolute) : CEDCNode::Ban(netAddr, BanReasonManuallyAdded, banTime, absolute);

        //disconnect possible nodes
        while(CEDCNode *bannedNode = (isSubnet ? edcFindNode(subNet) : edcFindNode(netAddr)))
            bannedNode->fDisconnect = true;
    }
    else if(strCommand == "remove")
    {
        if (!( isSubnet ? CEDCNode::Unban(subNet) : CEDCNode::Unban(netAddr) ))
            throw JSONRPCError(RPC_MISC_ERROR, "Error: Unban failed");
    }

    DumpBanlist(); //store banlist to disk
    uiInterface.BannedListChanged();

    return NullUniValue;
}

UniValue edclistbanned(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                            "eb_listbanned\n"
                            "\nList all banned IPs/Subnets.\n"
                            "\nExamples:\n"
                            + HelpExampleCli("eb_listbanned", "")
                            + HelpExampleRpc("eb_listbanned", "")
                            );

    banmap_t banMap;
    CEDCNode::GetBanned(banMap);

    UniValue bannedAddresses(UniValue::VARR);
    for (banmap_t::iterator it = banMap.begin(); it != banMap.end(); it++)
    {
        CBanEntry banEntry = (*it).second;
        UniValue rec(UniValue::VOBJ);
        rec.push_back(Pair("address", (*it).first.ToString()));
        rec.push_back(Pair("banned_until", banEntry.nBanUntil));
        rec.push_back(Pair("ban_created", banEntry.nCreateTime));
        rec.push_back(Pair("ban_reason", banEntry.banReasonToString()));

        bannedAddresses.push_back(rec);
    }

    return bannedAddresses;
}

UniValue edcclearbanned(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                            "eb_clearbanned\n"
                            "\nClear all banned IPs.\n"
                            "\nExamples:\n"
                            + HelpExampleCli("eb_clearbanned", "")
                            + HelpExampleRpc("eb_clearbanned", "")
                            );

    CEDCNode::ClearBanned();
    DumpBanlist(); //store banlist to disk
    uiInterface.BannedListChanged();

    return NullUniValue;
}

static const CRPCCommand edcCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "network",            "eb_getconnectioncount",     &edcgetconnectioncount,     true  },
    { "network",            "eb_ping",                   &edcping,                   true  },
    { "network",            "eb_getpeerinfo",            &edcgetpeerinfo,            true  },
    { "network",            "eb_addnode",                &edcaddnode,                true  },
    { "network",            "eb_disconnectnode",         &edcdisconnectnode,         true  },
    { "network",            "eb_getaddednodeinfo",       &edcgetaddednodeinfo,       true  },
    { "network",            "eb_getnettotals",           &edcgetnettotals,           true  },
    { "network",            "eb_getnetworkinfo",         &edcgetnetworkinfo,         true  },
    { "network",            "eb_setban",                 &edcsetban,                 true  },
    { "network",            "eb_listbanned",             &edclistbanned,             true  },
    { "network",            "eb_clearbanned",            &edcclearbanned,            true  },
};

void edcRegisterNetRPCCommands(CEDCRPCTable & edcTableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(edcCommands); vcidx++)
        edcTableRPC.appendCommand(edcCommands[vcidx].name, &edcCommands[vcidx]);
}