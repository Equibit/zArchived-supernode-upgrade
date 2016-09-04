#include "NFModule.h"
#include "NFApp.h"
#include "NFSecurityWorld.h"
#include "NFCardLoadingLib.h"
#include "NFError.h"
#include "NFHardServer.h"


namespace NFast
{

Module::Module( 
	SecurityWorld & sw, 
	CardLoadingLib & rqCard ): 
		world_(sw),
		cardLoadingLib_(rqCard),
		id_(0), 
		cardSetId_(0),
		cardSet_(nullptr)
{
	rqCard.loadOCS(cardSetHash_);
		
	int rc = RQCard_whichmodule_anyone( &cardLoadingLib_.rqCard(), &id_, &cardSetId_ );
	throwOnError( "Loading module", rc );

	init();
}

Module::Module( 
	 SecurityWorld & sw, 
	CardLoadingLib & rqCard, 
	      M_ModuleID mid ): 
	world_(sw),
	cardLoadingLib_(rqCard),
	id_(mid),
	cardSetId_(0),
	cardSet_(nullptr)
{
	rqCard.loadOCS(cardSetHash_);

	int rc = RQCard_whichmodule_specific(&cardLoadingLib_.rqCard(), id_, &cardSetId_ );
	throwOnError( "Loading module", rc );

	init();
}

void Module::init()
{
	int rc = cardLoadingLib_.rqCard().uf->eventloop(&cardLoadingLib_.rqCard());
	throwOnError( "Starting module event loop", rc );

	for( int n = 0; n < world_.info()->n_modules; ++n)
	{
		if(world_.info()->modules[n]->module == id_)
		{
			moduleInfo_ = world_.info()->modules[n];
			break;
		}
	}

	rc = NFKM_findcardset( world_.app().handle(), &cardSetHash_, &cardSet_, world_.app().cctx() );
	throwOnError( "Finding card set", rc );
}

Module::~Module()
{
	if(cardSetId_)
		NFKM_cmd_destroy(
			world_.app().handle(), 
			cardLoadingLib_.server().connection(), 
			id_, 
			cardSetId_, 
			"module id", 
			world_.app().cctx() );
    NFKM_freecardset( world_.app().handle(), cardSet_, world_.app().cctx() );
}

}
