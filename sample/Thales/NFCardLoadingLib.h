#pragma once

#include "nfast.h"

namespace NFast
{

class App;
class HardServer;
class SecurityWorld;


class CardLoadingLib
{
public:
	CardLoadingLib( App & app, HardServer & serv, SecurityWorld & sw );
	~CardLoadingLib();

	RQCard 		& rqCard()		{ return rqCard_; }
	RQCard_FIPS & rqCardFIPS() 	{ return rqCardFIPS_; }
    App 		& app()			{ return app_; }
	HardServer  & server()		{ return server_; }

	void loadOCS( NFKM_CardSetIdent & cardSethash );

private:
            App & app_;
	 HardServer & server_;
  SecurityWorld & world_;

	     RQCard	rqCard_;
	RQCard_FIPS rqCardFIPS_;
};

}
