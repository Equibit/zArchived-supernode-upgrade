#include "edcapp.h"
#include "edcparams.h"


const unsigned int EDC_DEFAULT_MAX_PEER_CONNECTIONS = 125;


EDCapp::EDCapp():
	debug_(false),
	maxConnections_ (EDC_DEFAULT_MAX_PEER_CONNECTIONS),
	minRelayTxFee_(EDC_DEFAULT_MIN_RELAY_TX_FEE),
	coinCacheUsage_(5000*300),
	mempool_(minRelayTxFee_)
{
	//TODO: Does maxConnects_ need to take into account the bitcoin connections?
}

EDCapp & EDCapp::singleton()
{
	static EDCapp theOneAndOnly;

	return theOneAndOnly;
}
