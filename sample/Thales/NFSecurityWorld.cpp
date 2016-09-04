#include "NFSecurityWorld.h"
#include "NFApp.h"
#include "NFError.h"


namespace NFast
{

SecurityWorld::SecurityWorld( App & app ):
	app_(app), info_(nullptr)
{
	int rc = NFKM_getinfo(app.handle(), &info_, app_.cctx() );
	throwOnError( "Getting Security World info", rc );
}

SecurityWorld::~SecurityWorld()
{
	NFKM_freeinfo( app_.handle(), &info_, app_.cctx() );
}
	
}
