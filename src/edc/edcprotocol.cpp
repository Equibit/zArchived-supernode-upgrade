// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcprotocol.h"

#include "edcutil.h"
#include "utilstrencodings.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif

namespace NetMsgType 
{
const char *USER="user";
};

namespace
{

const char * ppszTypeName[] =
{
    "ERROR", // Should never occur
    NetMsgType::TX,
    NetMsgType::BLOCK,
    "filtered block" // Should never occur
};

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const std::string edcallNetMessageTypes[] = 
{
    NetMsgType::VERSION,
    NetMsgType::VERACK,
    NetMsgType::ADDR,
    NetMsgType::INV,
    NetMsgType::GETDATA,
    NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS,
    NetMsgType::GETHEADERS,
    NetMsgType::TX,
    NetMsgType::HEADERS,
    NetMsgType::BLOCK,
    NetMsgType::GETADDR,
    NetMsgType::MEMPOOL,
    NetMsgType::PING,
    NetMsgType::PONG,
    NetMsgType::NOTFOUND,
    NetMsgType::FILTERLOAD,
    NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR,
    NetMsgType::REJECT,
    NetMsgType::SENDHEADERS,
    NetMsgType::FEEFILTER,
	NetMsgType::USER
};

const std::vector<std::string> edcallNetMessageTypesVec(
	edcallNetMessageTypes, 
	edcallNetMessageTypes+ARRAYLEN(edcallNetMessageTypes));

}

const std::vector<std::string> & edcgetAllNetMessageTypes()
{
    return edcallNetMessageTypesVec;
}
