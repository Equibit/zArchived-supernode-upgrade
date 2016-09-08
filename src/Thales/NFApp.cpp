#include "NFApp.h"
#include "NFError.h"

namespace NFast
{

App::App(
	NFast_MallocUpcall_t 	mallocUpcall,
	NFast_ReallocUpcall_t	reallocUpcall,
	NFast_FreeUpcall_t		freeUpcall,
	NFast_Call_Context 		* cctx ):cctx_(cctx)
{
	memset(&app_, 0, sizeof(app_));
	int rc = NFastApp_Init( &app_, mallocUpcall, reallocUpcall, freeUpcall, cctx );
	throwOnError("Initializing NF application", rc );
}

App::App(
	const NFastAppInitArgs * initArgs,
	struct NFast_Call_Context * cctx
):cctx_(cctx)
{
	memset(&app_, 0, sizeof(app_));
	int rc = NFastApp_InitEx( &app_, initArgs, cctx );
	throwOnError("Initializing NF application", rc );
}

App::~App()
{
	NFastApp_Finish( app_, cctx_ );
}

void App::setBignumUpcalls(
	NFast_BignumReceiveUpcall_t receiveUp,
	NFast_BignumSendLenUpcall_t sendLenUp,
	NFast_BignumSendUpcall_t	sendUp,
	NFast_BignumFreeUpcall_t	freeUp,
	NFast_BignumFormatUpcall_t  formatUp )
{
	int rc = NFastApp_SetBignumUpcalls( 
		app_,
		receiveUp,
		sendLenUp,
		sendUp,
		freeUp,
		formatUp,
		cctx_ );
	throwOnError("Setting application big number upcall functions", rc );
}

}
