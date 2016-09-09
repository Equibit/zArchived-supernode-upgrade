#include <stdexcept>
#include "NFApp.h"
#include "NFSecurityWorld.h"
#include "NFHardServer.h"
#include "NFModule.h"
#include "NFCardLoadingLib.h"
#include "NFCommand.h"
#include "NFFindKey.h"
#include <picky-upcalls.h>
#include <simplebignum.h>


struct NFast_Call_Context
{
	int not_sure_what_should_go_here;
};

/* Threading upcalls
 *
 * ncthread_upcalls provides a simple means to specify that the generic stub
 * should use the native threading primitives: typically <pthreads.h> on UNIX
 * platforms and CreateMutex/CreateThread/etc under Microsoft Windows.
 *
 * The generic stub threading upcalls structure requires one member beyond what
 * ncthread provides, to translate a call context instead the thread libraries
 * context pointer.  ncthread does not need a context pointer, so we always
 * translate it to a null pointer.
 *
 * If your application has some non-native thread model then you will need to
 * either fill in an nf_thread_upcalls structure with suitable upcalls and
 * possibly write an xlate function, or alternatively fill in an
 * NFast_ThreadUpcalls structure (and use NFAPP_IF_THREAD below instead of
 * NFAPP_IF_NEWTHREAD).
 */
/** Thread context translation upcall
 *
 * The ncthread upcalls do not need a thread context, so we always return a
 * thread context of 0 (the null pointer).
 */
static void xlate_cctx_to_ncthread(
	NFast_AppHandle app,
	struct NFast_Call_Context * cc,
	struct nf_lock_cctx ** lcc_r ) 
{
  *lcc_r = 0;
}

const NFast_NewThreadUpcalls newthreadupcalls = 
{
  &ncthread_upcalls,
  xlate_cctx_to_ncthread
};

/** Memory allocation upcalls
 *
 * By default the generic stub will manage memory using the standard C library
 * functions malloc, realloc and free.  By passing it a collection of malloc
 * upcalls it can instead use alternative functions.  For example, a heavily
 * threaded application might use per-thread allocators (and per-thread
 * apphandles) to avoid contention.
 *
 * In this example we just redirect back to the standard functions.
 *
 * The cctx and tctx arguments are passed down from the original call into the
 * generic stub or security world library function.  The exact meaning of both
 * is up to the application.
 */

/** Memory allocation upcall
 *
 * See mallocupcalls.
 */
static void *local_malloc(
	size_t nbytes,
	struct NFast_Call_Context *cctx,
	struct NFast_Transaction_Context *tctx) 
{
	return malloc(nbytes);
}

/** Memory allocation upcall
 *
 * See mallocupcalls.
 */
static void *local_realloc(	
	void * ptr,
	size_t nbytes,
	struct NFast_Call_Context * cctx,
	struct NFast_Transaction_Context * tctx) 
{
	return realloc(ptr, nbytes);
}

/** Memory deallocation upcall
 *
 * See mallocupcalls.
 */
static void local_free(
	void *ptr,
	struct NFast_Call_Context *cctx,
	struct NFast_Transaction_Context *tctx) 
{
	free(ptr);
}

const NFast_MallocUpcalls mallocupcalls = 
{
	local_malloc,
	local_realloc,
	local_free
};


namespace NFast
{

bool init(  
			   App * & appPtr,
	 SecurityWorld * & swPtr,
		HardServer * & hsPtr,
	CardLoadingLib * & cllPtr,
			Module * & mdPtr )
{
	appPtr = NULL;
	swPtr  = NULL;
	hsPtr  = NULL;
	cllPtr = NULL;
	mdPtr  = NULL;

   	NFast_Call_Context	* cctx 			= NULL;
	NFastAppInitArgs	* app_init_args = NULL;

	try
	{
		cctx = new NFast_Call_Context;
		app_init_args = new NFastAppInitArgs;

		memset( app_init_args, 0, sizeof *app_init_args );

		app_init_args->flags = NFAPP_IF_MALLOC|NFAPP_IF_BIGNUM|NFAPP_IF_NEWTHREAD;
		app_init_args->mallocupcalls 	= &mallocupcalls;
		app_init_args->bignumupcalls	= &sbn_upcalls;
		app_init_args->newthreadupcalls	= &newthreadupcalls;

		appPtr = new App( app_init_args, cctx );
		swPtr  = new SecurityWorld( *appPtr );
		hsPtr  = new HardServer( *appPtr, 0 );
		cllPtr = new CardLoadingLib( *appPtr, *hsPtr, *swPtr );
		mdPtr  = new Module( *swPtr, *cllPtr );
	}
	catch(...)
	{
		delete appPtr;
		delete swPtr;
		delete hsPtr;
		delete cllPtr;
		delete mdPtr;

   		delete cctx;
		delete app_init_args;

		return false;
	}

	return true;
}

void terminate(  
			   App * & appPtr,
	 SecurityWorld * & swPtr,
		HardServer * & hsPtr,
	CardLoadingLib * & cllPtr,
			Module * & mdPtr )
{
	delete appPtr;
	delete swPtr;
	delete hsPtr;
	delete cllPtr;
	delete mdPtr;

	appPtr = NULL;
	swPtr  = NULL;
	hsPtr  = NULL;
	cllPtr = NULL;
	mdPtr  = NULL;
}


};

