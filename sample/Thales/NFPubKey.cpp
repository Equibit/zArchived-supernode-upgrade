#include "NFPubKey.h"
#include "NFFindKey.h"
#include "NFHardServer.h"
#include "NFCommand.h"
#include "NFError.h"


namespace NFast
{

PubKey::PubKey( 
		HardServer & hardServer, 
			Module & module, 
	const KeyIdent & id ):
		app_(hardServer.app()), 
		ident_(id)
{
	memset( data_, 0, sizeof data_ );

	FindKey	find( app_, id );

	// If the key could not be found and force generation is set
	if( find.info() )
	{
		Export exp( hardServer, module, ident_ );
		int rc = exp.transact( hardServer );
		throwOnError( "export key", rc );

		M_KeyData data = exp.data();

		sbn_bignumsendupcall(hardServer.app().handle(),
						 	 hardServer.app().cctx(),
							 NULL,
                        	 &data.data.ecpublic.Q.x, 
							 32,
                        	 data_, 
							 1, 
							 1 );
		sbn_bignumsendupcall(hardServer.app().handle(),
							 hardServer.app().cctx(),
							 NULL,
                        	 &data.data.ecpublic.Q.y, 
							 32,
                        	 data_+32, 
							 1, 
							 1 );
	}
}

PubKey::PubKey( 
	HardServer & hardServer, 
		Module & module, 
const KeyIdent & keyID, 
	   M_KeyType keyType, 
			 int flags, 
			 int protectType, 
			 int recoverType ):
		app_(hardServer.app()),
		ident_(keyID)
{
	memset( data_, 0, sizeof data_ );

	GenerateKeyPair	cmd( hardServer, module, keyID, keyType, 
						flags, protectType, recoverType );

	int rc = cmd.transact( hardServer );
	throwOnError( "Generating key pair", rc );
	
	Export exp( hardServer, module, ident_ );
	rc = exp.transact( hardServer );
	throwOnError( "export key", rc );

	M_KeyData data = exp.data();

	sbn_bignumsendupcall(hardServer.app().handle(),
						 hardServer.app().cctx(),
						 NULL,
                         &data.data.ecpublic.Q.x, 
						 32,
                         data_, 
						 1, 
						 1 );
	sbn_bignumsendupcall(hardServer.app().handle(),
						 hardServer.app().cctx(),
						 NULL,
                         &data.data.ecpublic.Q.y, 
						 32,
                         data_+32, 
						 1, 
						 1 );
}

}
