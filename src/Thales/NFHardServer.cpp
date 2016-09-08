#include "NFHardServer.h"
#include "NFError.h"

namespace NFast
{

HardServer::HardServer( App & app, uint32 flags ):
	app_(app),
	flags_(flags)
{
	memset( &conn_, 0, sizeof conn_ );
	int rc = NFastApp_Connect( app_.handle(), &conn_, flags_, app_.cctx() );
	throwOnError("Connecting to hardserver", rc);
}

HardServer::~HardServer()
{
	int rc = NFastApp_Disconnect( conn_, app_.cctx() );
	printOnError("Disconnecting to hardserver", rc);
}

void HardServer::setClientId( NFast_Client_Ident * cid )
{
	int rc = NFastApp_SetClientIdent( app_.handle(), cid, app_.cctx() );
	throwOnError("Setting hardserver client id", rc);
}

void HardServer::getClientId( NFast_Client_Ident * cid )
{
	int rc = NFastApp_GetClientIdent( app_.handle(), cid, app_.cctx() );
	throwOnError("Getting hardserver client id", rc);
}

}
