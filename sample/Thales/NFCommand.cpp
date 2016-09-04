#include "NFCommand.h"
#include "NFHardServer.h"
#include "NFError.h"
#include "NFModule.h"
#include "NFSecurityWorld.h"
#include "NFCardLoadingLib.h"
#include "NFFindKey.h"
#include <stdexcept>
#include <endian.h>


/////////////////////////////////////////////////////////

namespace NFast
{

namespace
{

bool isAsymetricKey( M_KeyType keyType )
{
	switch(keyType)
	{
	// asymmetric
	case KeyType_RSAPublic:
	case KeyType_RSAPrivate:
	case KeyType_DSAPublic:
	case KeyType_DHPublic:
	case KeyType_DHPrivate:
	case KeyType_DSAPrivate:
	case KeyType_DSAComm:
	case KeyType_KCDSAPublic:
	case KeyType_KCDSAPrivate:
	case KeyType_ECPublic:
	case KeyType_ECPrivate:
	case KeyType_ECDSAPublic:
	case KeyType_ECDSAPrivate:
	case KeyType_ECDHPrivate:
	case KeyType_ECDHPublic:
	case KeyType_ECDHLaxPrivate:
	case KeyType_ECDHLaxPublic:
		return true;
	
	// symmetric
	case KeyType_Any:
	case KeyType__Max:

	case KeyType_Random:
	case KeyType_DES:
	case KeyType_DES3:
	case KeyType_None:
	case KeyType_ArcFour:
	case KeyType_CAST:
	case KeyType_Void:
	case KeyType_Wrapped:
	case KeyType_DKTemplate:
	case KeyType_HMACMD5:
	case KeyType_HMACSHA1:
	case KeyType_HMACRIPEMD160:
	case KeyType_Serpent:
	case KeyType_Rijndael:
	case KeyType_Twofish:
	case KeyType_CAST256:
	case KeyType_Blowfish:
	case KeyType_HMACSHA256:
	case KeyType_HMACSHA384:
	case KeyType_HMACSHA512:
	case KeyType_HMACTiger:
	case KeyType_SSLMasterSecret:
	case KeyType_DES2:
	case KeyType_KCDSAComm:
	case KeyType_SEED:
	case KeyType_HMACSHA224:
	case KeyType_ARIA:
	case KeyType_Camellia:
	case KeyType_DSACommVariableSeed:
	case KeyType_DSACommFIPS186_3:
		return false;
	}
	return false;
}

int is_signing_only_keytype(M_KeyType keytype) 
{
	switch(keytype) 
	{
	case KeyType_DSAPrivate:
	case KeyType_ECDSAPrivate:
	case KeyType_ECDHPrivate: return 1;
	default:                  return 0;
	}
}

int is_encryption_only_keytype(M_KeyType keytype) 
{
	switch(keytype) 
	{
	case KeyType_DHPrivate:
	case KeyType_KCDSAPrivate:
	case KeyType_ECDSAPrivate: return 1;
	default:                   return 0;
	}
}

namespace
{

int newBignum( 
		   App & app,
			 int,
	const char * hexStr,
	  M_Bignum * out )
{
#if 1
	return sbn_char2bignum( out,
							hexStr,
							app.handle(),
							NULL,
							NULL );
#else
	constexpr bool IS_BIG_ENDIAN = BYTE_ORDER == BIG_ENDIAN;

	return sbn_bignumreceiveupcall( app.handle(),
									nullptr,
									nullptr,
									out,
									len,
									hexStr,
									IS_BIG_ENDIAN,
									IS_BIG_ENDIAN );
#endif
}

}

void initKeyGen(
			 M_Command & cmd,
			   M_KeyType keyType,
				Module & module,
NFKM_FIPS140AuthHandle & fips140authhandle
)
{
	/* As well as the broad categories of keys dealt with above, each key type
	 * may have its own specific key generation parameters.  We deal with these
	 * for a subset of possible key types here. */
	switch(keyType) 
	{
	case KeyType_Rijndael:
		/* We ask for a 128 bit key. */
		cmd.args.generatekey.params.params.random.lenbytes = 128/8;
		break;
	case KeyType_DSAPrivate:
		/* We ask for a 1024 bit key and strict key verification.  We don't 
		 * supply a discrete log group, instead expecting the module to choose 
		 * a suitable one automatically. 
		 */
		cmd.args.generatekeypair.params.params.dsaprivate.flags = 
			KeyType_DSAPrivate_GenParams_flags_Strict;
		cmd.args.generatekeypair.params.params.dsaprivate.lenbits = 1024;
		break;
	case KeyType_ECDSAPrivate:
	{
		cmd.args.generatekeypair.params.params.ecprivate.curve.name = 
			ECName_Custom;
		auto & custom = cmd.args.generatekeypair.params.params.ecprivate.
							curve.data.custom;

		App & app = module.world().app();

		// See https://en.bitcoin.it/wiki/Secp256k1
		//

		// M_Field
		// M_FieldType
		custom.F.type = FieldType_Prime; // It is defined over Zp field

		// M_FieldType__Data
		const char * p ="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
						"FFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
		int rc = newBignum( app, 64, p, &custom.F.data.prime.p );

		custom.F.data.prime.flags = 0;

		// M_FieldElement (== M_Bignum)
		const char * a ="00000000000000000000000000000000"
						"00000000000000000000000000000000";
		rc |= newBignum( app, 64, a, &custom.a );

		// M_FieldElement (== M_Bignum)
		const char * b ="00000000000000000000000000000000"
						"00000000000000000000000000000007";
		rc |= newBignum( app, 64, b, &custom.b );

		// M_ECPoint
		const char * g_x = "79BE667EF9DCBBAC55A06295CE870B07"
						   "029BFCDB2DCE28D959F2815B16F81798";
		const char * g_y = "483ADA7726A3C4655DA4FBFC0E1108A8"
						   "FD17B448A68554199C47D08FFB10D4B8";
		rc |= newBignum( app, 64, g_x, &custom.g.x );
		rc |= newBignum( app, 64, g_y, &custom.g.y );

		// M_Bignum
		const char * r ="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
						"BAAEDCE6AF48A03BBFD25E8CD0364141";
		rc |= newBignum( app, 64, r, &custom.r );

		// M_Word
		custom.h = 1;

		if( rc )
			throw std::runtime_error( "Failed to create EC curve" );
		break;
	}
	default:
		/* We don't know about other key types. */
		throw std::runtime_error("Unsupported key type "
			"passed to key generator");
	}

	fips140authhandle = 0;

	/* If the module is in strict-FIPS mode then we will need to provide FIPS
	 * auth when generating the key.  The card loader is capable of providing
	 * this.  If we already loaded cards then it will have picked up FIPS aith
	 * from them along the way and the first call will succeed. */
	int rc = RQCard_fips_get( 
		&module.cardLoadingLib().rqCardFIPS(), 
		module.info()->module, 
		&fips140authhandle,
		0/*errorslot_r*/);

	if(rc == Status_RQCardMustContinue) 
	{
		/* We didn't pick up FIPS auth from loaded cards.  We ask the card-loader
		* to retrieve it explicitly. */
		rc = RQCard_fips_logic(&module.cardLoadingLib().rqCard());
		throwOnError( "FIPS Logic", rc );

		/* We must tell it which module we're using. */
		rc = RQCard_whichmodule_specific( 
			&module.cardLoadingLib().rqCard(), 
			module.info()->module, 
			0);
		throwOnError( "Find module", rc );

		/* Run the card-loader. */
		rc = module.cardLoadingLib().rqCard().uf->eventloop(
			&module.cardLoadingLib().rqCard());
		throwOnError( "Running card loader", rc );
		rc = RQCard_fips_get(
			&module.cardLoadingLib().rqCardFIPS(), 
			module.info()->module, 
			&fips140authhandle,
			0/*errorslot_r*/);
	}
	throwOnError( "Getting FIPS", rc );

	rc = NFKM_newkey_makeauth(
		module.world().app().handle(), 
		module.world().info(), 
		&cmd.flags, 
		&cmd.certs,
		fips140authhandle, 
		module.world().app().cctx() );
	throwOnError( "New key make auth", rc );
	/* fips140authhandle will be destroyed when rqcard_fips is */
}

M_Status check_reply(
			  int  rc,
	const M_Reply* replyp,
	const char	 * what) 
{
	/* The return value from NFastApp_Transact() reflects communication errors -
	 * for instance, not being able to contact the hardserver. */
	throwOnError( "Command submission", rc);

	/* replyp->status reflects errors reported by the module - for instance, if
	 * the key's ACL prevents us from performing the operation required. */
	if(replyp != 0 && replyp->status) 
	{
		NFast_Perror(what, replyp->status);
		return replyp->status;
	}

	/* If we get here then the command must have succeeded. */
	return Status_OK;
}

int checkKeyGenReply( 
					 int rc,
			   M_Reply & reply,
			  KeyIdent & keyident,
  NFKM_MakeBlobsParams & mbp,
NFKM_FIPS140AuthHandle & fips140authhandle,
			NFKM_Key * & keyinfo,
			HardServer & hardServer,
				Module & module )
{
	/* We have generated a new key (or key pair) but as yet it exists only in the
	 * module's memory.  We must construct an NFKM_Key key information structure
	 * and then record it to disk.
	 */

	SecurityWorld & world = module.world();
	App & app = world.app();

	if(!(keyinfo = static_cast<NFKM_Key *>(NFastApp_Malloc(app.handle(), sizeof *keyinfo, app.cctx(), 0)))) 
	{
		fprintf(stderr, "out of memory\n");
		return Status_NoHostMemory;
	}
	memset(keyinfo, 0, sizeof *keyinfo);

	/* Some things we must fill in ourselves */
	keyinfo->v = 8;
	keyinfo->appname = keyident.data().appname;
	keyinfo->ident = keyident.data().ident;
	time(&keyinfo->gentime);

	/* Next we fill in the makeblob parameters structure, mbp, and notice whether
	 * a key generation certificate was included in the reply.  Normally this
	 * will always be present but we test for it nonetheless.
	 *
	 * mbp.f must be the same as the flags word passed to NFKM_newkey_makeaclx()
	 * when we created the private ACL.  To ensure this is so we set it
	 * accordingly above.
	 */
	M_ModuleCert *mc = 0;
	if(reply.cmd == Cmd_GenerateKeyPair) 
	{
		/* Generated an asymmetric key */
		mbp.kpriv = reply.reply.generatekeypair.keypriv;
		mbp.kpub = reply.reply.generatekeypair.keypub;

		if(reply.reply.generatekeypair.flags & Cmd_GenerateKeyPair_Reply_flags_certpriv_present)
			mc = reply.reply.generatekeypair.certpriv;
	} 
	else 
	{
		/* Generated a symmetric key */
		mbp.kpriv = reply.reply.generatekey.key;
		if(reply.reply.generatekey.flags & Cmd_GenerateKey_Reply_flags_cert_present)
			mc = reply.reply.generatekey.cert;
	}

	if(module.cardSet()) 
	{
		/* We need to fill in cardset details in order to make the blobs */
		mbp.lt = module.cardSetId();
		mbp.cs = module.cardSet();
	}
	mbp.fips = fips140authhandle;         /* only needed for NVRAM keys */
	
	/* Store blobs for our key
	*
	* For an asymmetric key type only one blob is saved, the private key blob.
	*
	* For a symmetric key type a public key blob is saved too.  This is still
	* encrypted but under a fixed global key (encoded in the library), so the
	* key can be loaded without any special permission.
	*/
	rc = NFKM_newkey_makeblobsx(app.handle(), hardServer.connection(), 
		world.info(), &mbp, keyinfo, app.cctx() );
	if(rc) 
	{
		printOnError( "Make blob", rc);
		return rc;
	}

	/* Store key generation certificate information for our key */
	if(mc) 
	{
		rc = NFKM_newkey_writecert(app.handle(), hardServer.connection(), 
			module.info(), mbp.kpriv, mc, keyinfo, app.cctx() );
		if(rc) 
		{
			printOnError("Write certificiate", rc);
			return rc;
		}
	}

	/* We have now filled in keyinfo.  Save the resulting key information
	* structure to disk */
	rc = NFKM_recordkey(app.handle(), keyinfo, app.cctx() );
	if(rc) 
	{
		printOnError("Record Key", rc);
		return rc;
	}

	return Status_OK;
}

}

Command::Command( App & app, M_Cmd c ):app_(app)
{
	memset(&cmd_, 0, sizeof(cmd_));
	cmd_.cmd = c;
}

Command::~Command()
{
	NFastApp_Free_Reply(app_.handle(), app_.cctx(), 0, &reply_ );
}

int Command::transact( HardServer & hs )
{
	memset(&reply_, 0, sizeof(reply_));

	int rc = NFastApp_Transact( hs.connection(), app_.cctx(), &cmd_, &reply_, NULL );

	if(rc != Status_OK )
	{
		printOnError( "Transaction failed", rc );
		return rc;
	}
  	assert(cmd_.cmd == reply_.cmd || reply_.cmd == Cmd_ErrorReturn );

	rc=reply_.status;
	if ( rc != Status_OK )
	{
		const char * ecmd = NF_Lookup(cmd_.cmd, NF_Cmd_enumtable);

		if ( ecmd==NULL ) 
			ecmd="<unknown>";

		char err_buf[256];
		NFast_StrError( err_buf, sizeof(err_buf), static_cast<M_Status>(rc), &reply_.errorinfo );

		fprintf(stderr, "ERROR:Command %s FAILED: %s\n", ecmd, err_buf);
// TODO: use edcLogPrintf
		return rc;
	}

	/* Check for errors */
	rc = check_reply(rc, &reply_, name() );

	if(rc)
		return rc;

	return Status_OK;
}

/////////////////////////////////////////////////////////

CreateBuffer::CreateBuffer( App & app, int module, M_Word len ):Command( app, Cmd_CreateBuffer )
{
	cmd_.args.createbuffer.module = module;
	cmd_.args.createbuffer.size   = len;
}

/////////////////////////////////////////////////////////

LoadBuffer::LoadBuffer( 
			  App & app,
			M_KeyID kid, 
				int flags, 
	unsigned char * buff, 
				int len ):Command( app, Cmd_LoadBuffer )
{
	cmd_.args.loadbuffer.id		= kid;
	cmd_.args.loadbuffer.flags	= flags;

    cmd_.args.loadbuffer.chunk.ptr = buff;
    cmd_.args.loadbuffer.chunk.len = len;
}

/////////////////////////////////////////////////////////

GenerateKeyPair::GenerateKeyPair(
			 HardServer & hardServer,
				 Module & module, 
		 const KeyIdent & keyIdent,
				M_KeyType keyType, 
		  			  int flags,
					  int protectType,
					  int recoverType
	):	Command( hardServer.app(), Cmd_GenerateKeyPair),
		hardServer_(hardServer),
		module_(module),
		keyIdent_(keyIdent),
		keyinfo_(nullptr)
{
	if(!isAsymetricKey( keyType ))
		throw std::runtime_error( "Attempt was made to generate key pair with symmetric key type" );

	cmd_.args.generatekeypair.params.type = keyType;
	cmd_.args.generatekeypair.flags       = flags;
	cmd_.args.generatekeypair.module      = module.id();

	/* The private key ACL
	 *
	 * We ask for whichever of sign and encrypt are suitable for the key type.
	 * We use the NFKM function to produce a suitable ACL.  The created ACL
	 * will be allocated via the memory allocation upcalls and can be modified
	 * if necessary; even if there are some modifications to make this may be a
	 * better approach than starting entirely from scratch.
	 */
	NFKM_MakeACLParams map;
	memset(&map, 0, sizeof map);

	map.f = recoverType|protectType;
	switch(protectType) 
	{
	case NFKM_NKF_ProtectionCardSet:
		map.cs = module.cardSet();
		break;
	case NFKM_NKF_ProtectionModule:
		break;
	case NFKM_NKF_ProtectionPassPhrase:
		// TODO: Is pass phrase protected available?
	default:
		throw std::runtime_error( "Key protection type not implemented" ); 
	}

	memset(&mbp_, 0, sizeof mbp_);

	mbp_.f = map.f;                      /* we'll need this later */
	if(is_signing_only_keytype(keyType))
		map.op_base = NFKM_DEFOPPERMS_SIGN;
	else if(is_encryption_only_keytype(keyType))
		map.op_base = NFKM_DEFOPPERMS_DECRYPT;
	else
		map.op_base = (NFKM_DEFOPPERMS_SIGN|NFKM_DEFOPPERMS_DECRYPT);

	int rc = NFKM_newkey_makeaclx(
		hardServer.app().handle(), 
		hardServer.connection(), 
		module.world().info(), 
		&map,
		&cmd_.args.generatekeypair.aclpriv, 
		hardServer.app().cctx() );

	throwOnError( "Make ALC for private key", rc );

	/* The corresponding public key ACL */
	memset(&map, 0, sizeof map);
	map.f = NFKM_NKF_PublicKey;

	if(is_signing_only_keytype(keyType))
		map.op_base = NFKM_DEFOPPERMS_VERIFY;
	else if(is_encryption_only_keytype(keyType))
		map.op_base = NFKM_DEFOPPERMS_ENCRYPT;
	else
		map.op_base = (NFKM_DEFOPPERMS_VERIFY|NFKM_DEFOPPERMS_ENCRYPT);

	rc = NFKM_newkey_makeaclx(
		hardServer.app().handle(), 
		hardServer.connection(), 
		module.world().info(), 
		&map,
		&cmd_.args.generatekeypair.aclpub, 
		hardServer.app().cctx() );
	throwOnError( "Make ALC for public key", rc );

	initKeyGen( cmd_, keyType, module, fips140authhandle_ );
}

GenerateKeyPair::~GenerateKeyPair()
{
	NFastApp_FreeACL(app_.handle(), app_.cctx(), 0, &cmd_.args.generatekeypair.aclpriv);
	NFastApp_FreeACL(app_.handle(), app_.cctx(), 0, &cmd_.args.generatekeypair.aclpub);

	if( reply_.reply.generatekeypair.keypriv )
		NFKM_cmd_destroy(
			app_.handle(), 
			hardServer_.connection(), 
			0, 
			reply_.reply.generatekeypair.keypriv,
			"generatekeypair.keypriv", 
			app_.cctx() );
	if( reply_.reply.generatekeypair.keypub )
		NFKM_cmd_destroy(
			app_.handle(), 
			hardServer_.connection(), 
			0, 
			reply_.reply.generatekeypair.keypub,
			"generatekeypair.keypub", 
			app_.cctx() );

	/* If we're in a strict-FIPS world then NFKM_newkey_makeauth() will have
	 * created a certificate list. */
	if(cmd_.flags & Command_flags_certs_present)
		NFastApp_Free_CertificateList(app_.handle(), app_.cctx(), 0, cmd_.certs);

	keyinfo_->appname = 0;
	keyinfo_->ident = 0;
	NFKM_freekey(app_.handle(), keyinfo_, app_.cctx() );
}

int GenerateKeyPair::transact( HardServer & hs )
{
	int rc = Command::transact( hs );

	return checkKeyGenReply(rc, reply_, keyIdent_, mbp_, fips140authhandle_, keyinfo_, hardServer_, module_ );
}

/////////////////////////////////////////////////////////

GenerateKey::GenerateKey(
			 HardServer & hardServer,
				 Module & module, 
		 const KeyIdent & keyIdent,
				M_KeyType keyType, 
					  int flags,
					  int protectType,
					  int recoverType
	):	Command( hardServer.app(), Cmd_GenerateKeyPair),
		hardServer_(hardServer),
		module_(module),
		keyIdent_(keyIdent),
		keyinfo_(nullptr)
{
	if(isAsymetricKey( keyType ))
		throw std::runtime_error( "Attempt was made to generate key with asymmetric key type" );

	cmd_.args.generatekeypair.params.type = keyType;
	cmd_.args.generatekeypair.flags       = flags;
	cmd_.args.generatekeypair.module      = module.id();

	NFKM_MakeACLParams map;
	memset(&map, 0, sizeof map);
	map.f = recoverType|protectType;

	switch(protectType) 
	{
	case NFKM_NKF_ProtectionCardSet:
		map.cs = module.cardSet();
		break;
	case NFKM_NKF_ProtectionModule:
		break;
	case NFKM_NKF_ProtectionPassPhrase:
		// TODO: Is pass phrase protected available?
	default:
		throw std::runtime_error( "Key protection type not implemented" ); 
	}

	mbp_.f = map.f;                      /* we'll need this later */
	map.op_base = (NFKM_DEFOPPERMS_SIGN
		|NFKM_DEFOPPERMS_VERIFY
		|NFKM_DEFOPPERMS_ENCRYPT
		|NFKM_DEFOPPERMS_DECRYPT);
	int rc = NFKM_newkey_makeaclx(
		hardServer.app().handle(), 
		hardServer.connection(), 
		module.world().info(), 
		&map,
		&cmd_.args.generatekey.acl, 
		hardServer.app().cctx() );
	throwOnError( "Make ALC for symmetric key", rc );

	initKeyGen( cmd_, keyType, module, fips140authhandle_ );
}

GenerateKey::~GenerateKey()
{
	NFastApp_FreeACL(app_.handle(), app_.cctx(), 0, &cmd_.args.generatekey.acl);

	NFKM_cmd_destroy(app_.handle(), hardServer_.connection(), 0, reply_.reply.generatekey.key,
		"generatekey.key", app_.cctx() );

	/* If we're in a strict-FIPS world then NFKM_newkey_makeauth() will have
	 * created a certificate list. */
	if(cmd_.flags & Command_flags_certs_present)
		NFastApp_Free_CertificateList(app_.handle(), app_.cctx(), 0, cmd_.certs);
}

int GenerateKey::transact( HardServer & hs )
{
	int rc = Command::transact( hs );

	return checkKeyGenReply(rc, reply_, keyIdent_, mbp_, fips140authhandle_, keyinfo_, hardServer_, module_ );
}

/////////////////////////////////////////////////////////

Hash::Hash(
		   App & app,
		  M_Mech mech,
	const char * in ):
	Command( app, Cmd_Hash )
{
	cmd_.args.hash.mech =  mech;
	cmd_.args.hash.plain.type = PlainTextType_Bytes;
	cmd_.args.hash.plain.data.bytes.data.ptr = 
		reinterpret_cast<unsigned char *>(const_cast<char *>(in));
	cmd_.args.hash.plain.data.bytes.data.len = strlen(in);
}

/////////////////////////////////////////////////////////

Verify::Verify( 
				App & app, 
 		 HardServer & hardServer, 
	 		 Module & module, 
			M_KeyType keyType, 
	 const KeyIdent & keyIdent, 
			   M_Mech mech,
	     const char * in,
 const M_CipherText & sig
):Command( app, Cmd_Verify ),
  hardServer_(hardServer),
  module_(module)
{
	FindKey key( app, keyIdent );

	if( !key.info() )
	{
		std::string msg = "Verify passed non-existent key ";
		msg += keyIdent.appName();
		msg += ":";
		msg += keyIdent.ident();
		throw std::runtime_error( msg );
	}
		
	const M_ByteBlock *blobptr;

	if(key.info()->pubblob.len)
		blobptr = &key.info()->pubblob;
	else
		blobptr = &key.info()->privblob;

	M_KeyID keyid = 0;

	/* Attempt to load the key blob.  NFKM_cmd_loadblob() deals with the
   	 * details of filling in the command and handling the reply; it would be
   	 * possible to construct an M_Command with Cmd_LoadBlob directly
     * instead.  */
   	int rc = NFKM_cmd_loadblob(
		app_.handle(), 
		hardServer_.connection(),
   		module_.info()->module,
   		blobptr,
		module.cardSetId(),
       	&keyid,      
       	"loading key blob",
       	app_.cctx() );
	throwOnError( "Loading Blob", rc );

	cmd_.args.verify.key = keyid;
	cmd_.args.verify.mech = mech;

	cmd_.args.verify.sig = sig;

	Hash	hash( app, Mech_SHA256Hash, in );
	rc = hash.transact( hardServer );
	throwOnError( "Hashing message", rc );

	M_CipherText h = hash.hash();

	cmd_.args.verify.plain.type = PlainTextType_Hash32;
	memcpy(	cmd_.args.verify.plain.data.hash.data.bytes, 
			h.data.sha256hash.h.bytes, 
			sizeof (M_Hash));
}

/////////////////////////////////////////////////////////

Sign::Sign( 
				App & app, 
 		 HardServer & hardServer, 
	 		 Module & module, 
			M_KeyType keyType, 
	 const KeyIdent & keyIdent, 
			   M_Mech mech,
	     const char * in
):Command( app, Cmd_Sign ),
  hardServer_(hardServer),
  module_(module)
{
	FindKey key( app, keyIdent );

	if( !key.info() )
	{
		std::string msg = "Verify passed non-existent key ";
		msg += keyIdent.appName();
		msg += ":";
		msg += keyIdent.ident();
		throw std::runtime_error( msg );
	}
		
	const M_ByteBlock * blobptr = &key.info()->privblob;
	      
	M_KeyID keyid;

   	/* Attempt to load the key blob.  NFKM_cmd_loadblob() deals with the
   	 * details of filling in the command and handling the reply; it would be
   	 * possible to construct an M_Command with Cmd_LoadBlob directly
   	 * instead.  
	 */
   	int rc = NFKM_cmd_loadblob(
		app_.handle(), 
		hardServer_.connection(),
   		module_.info()->module,
		blobptr,
		module.cardSetId(),
		&keyid,      
		"loading key blob",
		app_.cctx() );
	throwOnError( "Loading Blob", rc );

	Hash	hash( app, Mech_SHA256Hash, in );
	rc = hash.transact( hardServer );
	throwOnError( "Hashing message", rc );

	M_CipherText h = hash.hash();

	cmd_.args.sign.key = keyid;
	cmd_.args.sign.mech = mech;
	cmd_.args.sign.plain.type = PlainTextType_Hash32;

	memcpy(cmd_.args.sign.plain.data.hash.data.bytes, 
		h.data.sha256hash.h.bytes, sizeof (M_Hash));
}

}
