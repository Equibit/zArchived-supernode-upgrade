#pragma once

#include "nfast.h"


namespace NFast
{

class App
{
public:
	App(NFast_MallocUpcall_t, 
		NFast_ReallocUpcall_t,
		NFast_FreeUpcall_t,
		struct NFast_Call_Context * );

	App(const NFastAppInitArgs *,
		struct NFast_Call_Context * );

	~App();

	NFast_AppHandle		handle()	{ return app_; }
	NFast_Call_Context	* cctx()	{ return cctx_; }

	void setBignumUpcalls( 
                      NFast_BignumReceiveUpcall_t,
                      NFast_BignumSendLenUpcall_t,
                      NFast_BignumSendUpcall_t,
                      NFast_BignumFreeUpcall_t,
                      NFast_BignumFormatUpcall_t );

private:
	NFast_AppHandle 	app_;
	NFast_Call_Context	* cctx_;
};

}
