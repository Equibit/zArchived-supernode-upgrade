#pragma once

#include "nfast.h"
#include "NFApp.h"


namespace NFast
{

class HardServer
{
public:
	HardServer( App &, uint32 flags );
	~HardServer();

	void setClientId( NFast_Client_Ident * cid );
	void getClientId( NFast_Client_Ident * cid );

	NFastApp_Connection	& connection()	{ return conn_; }
    App 				& app()			{ return app_; }

private:
                App & app_;
  NFastApp_Connection conn_;
			   uint32 flags_;
};

}
