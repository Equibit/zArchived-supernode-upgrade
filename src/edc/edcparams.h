#pragma once

#include "amount.h"


const int64_t      EDC_DEFAULT_DB_CACHE               = 100;
const int64_t      EDC_MAX_DB_CACHE                   = sizeof(void*)>4?16384:1024;
const unsigned int EDC_MAX_OP_RETURN_RELAY            = 83;
const int          EDC_MAX_SCRIPTCHECK_THREADS        = 16;
const unsigned int EDC_MIN_BLOCKS_TO_KEEP             = 288;
const int64_t      EDC_MIN_DB_CACHE                   = 4;
const uint64_t     EDC_MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024;


const bool         EDC_DEFAULT_ACCEPT_DATACARRIER      = true;
const unsigned int EDC_DEFAULT_ANCESTOR_LIMIT          = 25;
const unsigned int EDC_DEFAULT_ANCESTOR_SIZE_LIMIT     = 101;

const unsigned int EDC_DEFAULT_BANSCORE_THRESHOLD      = 100;
const unsigned int EDC_DEFAULT_BLOCK_MAX_SIZE          = 750000;
const unsigned int EDC_DEFAULT_BLOCK_MIN_SIZE          = 0;
const unsigned int EDC_DEFAULT_BLOCK_PRIORITY_SIZE     = 0;
const bool         EDC_DEFAULT_BLOCKSONLY              = false;
const unsigned int EDC_DEFAULT_BYTES_PER_SIGOP         = 20;

const signed int   EDC_DEFAULT_CHECKBLOCKS             = EDC_MIN_BLOCKS_TO_KEEP;
const unsigned int EDC_DEFAULT_CHECKLEVEL              = 3;
const bool         EDC_DEFAULT_CHECKPOINTS_ENABLED     = true;
const int          EDC_DEFAULT_CONNECT_TIMEOUT         = 5000;

const unsigned int EDC_DEFAULT_DESCENDANT_LIMIT        = 25;
const unsigned int EDC_DEFAULT_DESCENDANT_SIZE_LIMIT   = 101;
const bool         EDC_DEFAULT_DISABLE_SAFEMODE        = false;

const bool         EDC_DEFAULT_ENABLE_REPLACEMENT      = true;

const bool         EDC_DEFAULT_FEEFILTER               = true;
const bool         EDC_DEFAULT_FORCEDNSSEED            = false;

const int          EDC_DEFAULT_HTTP_SERVER_TIMEOUT     = 30;
const int          EDC_DEFAULT_HTTP_THREADS            = 4;
const int          EDC_DEFAULT_HTTP_WORKQUEUE          = 16;

const unsigned int EDC_DEFAULT_LIMITFREERELAY          = 15;
const bool         EDC_DEFAULT_LISTEN_ONION            = true;
const bool         EDC_DEFAULT_LOGIPS                  = false;
const bool         EDC_DEFAULT_LOGTIMESTAMPS           = true;
const bool         EDC_DEFAULT_LOGTIMEMICROS           = false;

const unsigned int EDC_DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
const unsigned int EDC_DEFAULT_MAX_MEMPOOL_SIZE        = 300;
const unsigned int EDC_DEFAULT_MAX_PEER_CONNECTIONS    = 125;
const unsigned int EDC_DEFAULT_MAX_SIG_CACHE_SIZE      = 40;
const int64_t      EDC_DEFAULT_MAX_TIME_ADJUSTMENT     = 70 * 60;
const int64_t      EDC_DEFAULT_MAX_TIP_AGE             = 24 * 60 * 60;
const uint64_t     EDC_DEFAULT_MAX_UPLOAD_TARGET       = 0;
const size_t       EDC_DEFAULT_MAXRECEIVEBUFFER        = 5 * 1000;
const size_t       EDC_DEFAULT_MAXSENDBUFFER           = 1 * 1000;
const unsigned int EDC_DEFAULT_MEMPOOL_EXPIRY          = 72;
const unsigned int EDC_DEFAULT_MIN_RELAY_TX_FEE        = 1000;
const unsigned int EDC_DEFAULT_MISBEHAVING_BANTIME     = 60 * 60 * 24;  // Default 24-hour ban

const int          EDC_DEFAULT_NAME_LOOKUP             = true;

const bool         EDC_DEFAULT_PEERBLOOMFILTERS        = true;
const bool         EDC_DEFAULT_PERMIT_BAREMULTISIG     = true;
const bool         EDC_DEFAULT_PRINTPRIORITY           = false;
const bool         EDC_DEFAULT_PROXYRANDOMIZE          = true;

const bool         EDC_DEFAULT_RELAYPRIORITY           = true;
const bool         EDC_DEFAULT_REST_ENABLE             = false;

const int          EDC_DEFAULT_SCRIPTCHECK_THREADS     = 0;
const bool         EDC_DEFAULT_STOPAFTERBLOCKIMPORT    = false;

const bool         EDC_DEFAULT_TESTSAFEMODE            = false;
const CAmount      EDC_DEFAULT_TRANSACTION_MAXFEE      = 0.1 * COIN;
const bool         EDC_DEFAULT_TXINDEX                 = false;

const bool         EDC_DEFAULT_WHITELISTFORCERELAY     = true;
const bool         EDC_DEFAULT_WHITELISTRELAY          = true;

extern const std::string EDC_DEFAULT_TOR_CONTROL;


// Equibit specific parameters
//
class EDCparams
{
public:

};
