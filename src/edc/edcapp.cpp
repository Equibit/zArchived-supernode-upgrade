#include "edcapp.h"
#include "edcparams.h"
#include "net.h"


namespace
{
const unsigned int EDC_DEFAULT_MAX_PEER_CONNECTIONS = 125;
const CAmount EDC_DEFAULT_TRANSACTION_FEE = 0;
}

EDCapp::EDCapp():
	debug_(false),
	maxConnections_ (EDC_DEFAULT_MAX_PEER_CONNECTIONS),
	coinCacheUsage_(5000*300),
	minRelayTxFee_(EDC_DEFAULT_MIN_RELAY_TX_FEE),
	mempool_(minRelayTxFee_),
	mapAlreadyAskedFor_(MAX_INV_SZ),
	payTxFee_(EDC_DEFAULT_TRANSACTION_FEE)
{
	//TODO: Does maxConnects_ need to take into account the bitcoin connections?
}

EDCapp & EDCapp::singleton()
{
	static EDCapp theOneAndOnly;

	return theOneAndOnly;
}
