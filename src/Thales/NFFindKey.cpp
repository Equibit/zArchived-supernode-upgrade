#include "NFFindKey.h"
#include "NFApp.h"
#include "NFError.h"
#include <stdexcept>


namespace NFast
{

FindKey::FindKey( App & app, const KeyIdent & ident ):app_(app),info_(NULL)
{
	int rc = NFKM_findkey( app_.handle(), ident.data(), &info_, app_.cctx() );
	// Note that rc == Status_OK even if no key with the specified
	// appName/ident exists
	throwOnError( "find key", rc );
}


FindKey::~FindKey( )
{
	if( info_ )
	{
		info_->appname = NULL;
		info_->ident = NULL;
		NFKM_freekey(app_.handle(), info_, app_.cctx() );
	}
}

}
