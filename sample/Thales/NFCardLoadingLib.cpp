#include "NFCardLoadingLib.h"
#include "NFError.h"
#include "NFApp.h"
#include "NFSecurityWorld.h"
#include "NFHardServer.h"


namespace NFast
{

CardLoadingLib::CardLoadingLib( 
				  App & app, 
	 	   HardServer & serv, 
		SecurityWorld & sw ):
	app_(app),
	server_(serv),
	world_(sw)
{
	int rc = RQCard_init( &rqCard_, app.handle(), server_.connection(), world_.info(), app.cctx() );
	throwOnError( "Card loader initialization", rc );	
	
	rc = RQCard_fips_init( &rqCard_, &rqCardFIPS_ );
	throwOnError( "Card loader FIPS initialization", rc );	

	rc = RQCard_ui_default(&rqCard_);
	throwOnError( "Default UI", rc );
}

CardLoadingLib::~CardLoadingLib()
{
	RQCard_fips_free(&rqCard_, &rqCardFIPS_);
	RQCard_destroy(&rqCard_);
}

void CardLoadingLib::loadOCS( NFKM_CardSetIdent & cardSetHash )
{
	memset( &cardSetHash, 0, sizeof(cardSetHash));

	int rc = RQCard_logic_ocs_anyone( &rqCard_, &cardSetHash, "Insert a card set to protect the new keys" );
	throwOnError("Loading OCS card", rc);
}

}
