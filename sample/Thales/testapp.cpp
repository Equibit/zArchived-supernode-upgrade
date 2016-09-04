
#include <iostream>
#include <stdexcept>
#include "NFApp.h"
#include "NFHardServer.h"
#include "NFSecurityWorld.h"
#include "NFCardLoadingLib.h"
#include "NFModule.h"
#include "NFCommand.h"
#include "NFFindKey.h"
#include "picky-upcalls.h"
#include "simplebignum.h"


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
static void xlate_cctx_to_ncthread(NFast_AppHandle app,
                                   struct NFast_Call_Context *cc,
                                   struct nf_lock_cctx **lcc_r) {
  *lcc_r = 0;
}

const NFast_NewThreadUpcalls newthreadupcalls = {
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
static void *local_malloc(size_t nbytes,
                          struct NFast_Call_Context *cctx,
                          struct NFast_Transaction_Context *tctx) {
  return malloc(nbytes);
}

/** Memory allocation upcall
 *
 * See mallocupcalls.
 */
static void *local_realloc(void *ptr,
                           size_t nbytes,
                           struct NFast_Call_Context *cctx,
                           struct NFast_Transaction_Context *tctx) {
  return realloc(ptr, nbytes);
}

/** Memory deallocation upcall
 *
 * See mallocupcalls.
 */
static void local_free(void *ptr,
                       struct NFast_Call_Context *cctx,
                       struct NFast_Transaction_Context *tctx) {
  free(ptr);
}

const NFast_MallocUpcalls mallocupcalls = {
  local_malloc,
  local_realloc,
  local_free
};


int main( int c, char * a[] )
{
    NFast_Call_Context cctx;
	try
	{
		NFastAppInitArgs app_init_args;
		memset(&app_init_args, 0, sizeof app_init_args);
		app_init_args.flags = NFAPP_IF_MALLOC|NFAPP_IF_BIGNUM|NFAPP_IF_NEWTHREAD;
		app_init_args.mallocupcalls = &mallocupcalls;
		app_init_args.bignumupcalls = &sbn_upcalls;
		app_init_args.newthreadupcalls = &newthreadupcalls;

		NFast::App				theApp( &app_init_args, &cctx );
		NFast::SecurityWorld	theSW( theApp );
		NFast::HardServer		theHS( theApp, 0 );
		NFast::CardLoadingLib	theCLL( theApp, theHS, theSW );
		NFast::Module			theModule( theSW, theCLL );
		
		bool useECDSA = false;

		if( c < 3 )
		{
			fprintf( stderr, "usage: %s ECDSA|DSA key-ident ...\n", a[0] );
			return 1;
		}
		else
		{
			useECDSA = (strcmp( a[1], "ECDSA" ) == 0);
		}

		M_KeyType	keyType = useECDSA? 
								KeyType_ECDSAPrivate:
								KeyType_DSAPrivate;
		int flags			= Cmd_GenerateKeyPair_Args_flags_Certify;
		int protectType		= NFKM_NKF_ProtectionCardSet;
		int recoverType 	= NFKM_NKF_RecoveryEnabled; 

		for( int i = 2; i < c; ++i )
		{
			NFast::KeyIdent keyID("equibit", a[i]);

			NFast::FindKey	findkey( theApp, keyID );

			if( !findkey.info() )
			{
				fprintf( stdout, "generating or using key key_equibit_%s\n", 
					a[i] );
				NFast::GenerateKeyPair	cmd(theHS, theModule, keyID, keyType, 
											flags, protectType, recoverType );

				int rc = cmd.transact( theHS );
				if( rc != Status_OK )
				{
					fprintf( stderr, "Key generation failed\n" );
					return 2;
				}
			}
			else
			{
				printf( "The key %s:%s already exists\n", keyID.appName(), 
					keyID.ident() );
			}

			M_Mech mech = useECDSA ? Mech_ECDSAhSHA256: Mech_DSA;

			const char * plain = "Some plain text to be digitally signed by "
				"our newly created private key. The text should be longer then "
				"the hash to make it a useful task";

			NFast::Sign	sign(theApp, theHS, theModule, keyType, keyID, 
							 mech, plain );

			int rc = sign.transact( theHS );
			if( rc != Status_OK )
			{
				fprintf( stderr, "Signature failed\n" );
				return 2;
			}
	
			M_CipherText sig = sign.signature();
//			printf( "Signature:" );
//			sbn_printbignum( stdout, "R", sig.data.ecdsa.r	);
//			sbn_printbignum( stdout, "S", sig.data.ecdsa.s );
	
			NFast::Verify verify( theApp, theHS, theModule, keyType, keyID,
				Mech_Any, plain, sig );
			rc = verify.transact( theHS );
			if( rc != Status_OK )
			{
				fprintf( stderr, "Verification failed\n" );
				return 2;
			}
		}
	}
	catch( std::runtime_error & ex )
	{
		std::cerr << "Terminated by uncaught exception: " << ex.what() << 
			std::endl;
		return 1;
	}

	return 0;
}
