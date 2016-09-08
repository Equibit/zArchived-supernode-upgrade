#pragma once

#include "nfast.h"

namespace NFast
{

class App;

class SecurityWorld
{
public:
	SecurityWorld( App & app );
	~SecurityWorld();
	
	NFKM_WorldInfo * info()	{ return info_; }
	App	& app()				{ return app_; }

private:
               App & app_;
	NFKM_WorldInfo * info_;
};

}
