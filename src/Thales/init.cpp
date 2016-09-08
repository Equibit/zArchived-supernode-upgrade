#include "NFApp.h"
#include "NFSecurityWorld.h"
#include "NFHardServer.h"
#include "NFModule.h"
#include "NFCardLoadingLib.h"


namespace NFast
{

bool init(  
			   App * &,
	 SecurityWorld * &,
		HardServer * &,
	CardLoadingLib * &,
			Module * & )
{

	return true;
}

};
