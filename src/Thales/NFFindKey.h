#pragma once

#include "nfast.h"
#include "NFKeyIdent.h"
#include <string>


namespace NFast
{

class App;

class FindKey
{
public:
	FindKey( App & app, const KeyIdent & id );
	~FindKey( );

	NFKM_Key	* info()	{ return info_; }

private:
		 App & app_;
	NFKM_Key * info_;
};

}
