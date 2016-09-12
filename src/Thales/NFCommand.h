#pragma once

#include "nfast.h"
#include "NFKeyIdent.h"

namespace NFast
{

class App;
class HardServer;
class Module;


class Command
{
public:
	Command( App & app, M_Cmd c );
	virtual ~Command();

	virtual int transact( HardServer & );
	virtual const char * name() const = 0;

protected:
	App			& app_;
	M_Command	cmd_;
	M_Reply		reply_;
};


/** Create a buffer and return an ID for it.
 ** 
 ** A buffer in this context is a fixed length area filled by subsequent
 ** @ref Cmd_LoadBuffer commands.
 ** 
 ** If the information is encrypted, you must have already loaded a key
 ** that can decrypt it, and you must include the KeyID and initialization
 ** vector to be used.
  *
  * See \ref Cmd_CreateBuffer for more information.
  */
class CreateBuffer: public Command
{
public:
	CreateBuffer( App &, int module, M_Word len );

	const char * name() const final	{ return "CreateBuffer"; }
};

/** Append some data to a given buffer.
 ** 
 ** Buffers are created with @ref Cmd_CreateBuffer.
  *
  * See \ref Cmd_LoadBuffer for more information.
  */
class LoadBuffer: public Command
{
public:
	LoadBuffer( App &, M_KeyID, int flags, unsigned char *, int len );

	const char * name() const final	{ return "LoadBuffer"; }
};

/** Generate an asymmetric key
 ** 
 **  If the FIPS140Level3 flag was set in @ref Cmd_SetNSOPerms, GenerateKeyPair
 **  will fail with status @ref Status_StrictFIPS140 if you attempt to generate
 **  a private key with an ACL that allows it to be exported as plain text.
  *
  * See \ref Cmd_GenerateKeyPair for more information.
  */
class GenerateKeyPair: public Command
{
public:
	GenerateKeyPair( HardServer &, Module &, const KeyIdent &, M_KeyType, int flags, int protectType, int recoverType );
	~GenerateKeyPair();

	const char * name() const final	{ return "GenerateKeyPair"; }

	int transact( HardServer & ) final;

private:
			HardServer & hardServer_;
				Module & module_;
				KeyIdent keyIdent_;
	NFKM_MakeBlobsParams mbp_;
  NFKM_FIPS140AuthHandle fips140authhandle_;
			  NFKM_Key * keyinfo_;
};

/** Generate a symmetric key
 ** 
 **  If the FIPS140Level3 flag was set in the @ref Cmd_SetNSOPerms, GenerateKey
 **  will fail with status @ref Status_StrictFIPS140 if you attempt to generate a
 **  key of a type that can have Sign or Decrypt permissions with an
 **  ACL that allows it to be exported as plain text.
  *
  * See \ref Cmd_GenerateKey for more information.
  */
class GenerateKey: public Command
{
public:
	GenerateKey( HardServer &, Module &, const KeyIdent &, M_KeyType, int flags, int protectType, int recoverType );
	~GenerateKey();

	const char * name() const final	{ return "GenerateKey"; }

	int transact( HardServer & ) final;

private:
			HardServer & hardServer_;
				Module & module_;
				KeyIdent keyIdent_;
	NFKM_MakeBlobsParams mbp_;
  NFKM_FIPS140AuthHandle fips140authhandle_;
			  NFKM_Key * keyinfo_;
};

/** Calculate the hash of a message
  *
  * See \ref Cmd_Hash for more information.
  */
class Hash: public Command
{
public:
	Hash(	App & app,
	  	   M_Mech mech,
	 const char * in );

	M_CipherText hash() const { return reply_.reply.hash.sig; }

	const char *	name() const final { return "hash"; }
};


/** Verifies a digital signature.
 ** 
 ** It returns @ref Status_OK if the signature verifies correctly and
 ** @ref Status_VerifyFailed if the verification fails.
  *
  * See \ref Cmd_Verify for more information.
  */
class Verify: public Command
{
public:
	Verify( 
		HardServer &, 
		Module &, 
		M_KeyType, 
		const KeyIdent &, 
		M_Mech, 
		const char *,
		const M_CipherText & );

	const char * name() const final	{ return "Verify"; }

private:
	HardServer & hardServer_;
	Module	   & module_;
};

/** Create a digital signature.
 ** 
 **  This command signs a message with a stored key. Sign pads the message as
 **  specified by the relevant algorithm, unless you use plaintext of type
 **  @ref PlainTextType_Bignum.
  *
  * See \ref Cmd_Sign for more information.
  */
class Sign: public Command
{
public:

	Sign( 
		HardServer &, 
		Module &, 
		M_KeyType, 
		const KeyIdent &, 
		M_Mech,
		const unsigned char * hash );

	Sign( 
		HardServer &, 
		Module &, 
		M_KeyType, 
		const KeyIdent &, 
		M_Mech,
		const char * plain );

	const char * name() const final	{ return "Sign"; }
	M_CipherText  signature() const { return reply_.reply.sign.sig; }

private:
	HardServer	& hardServer_;
	Module		& module_;
};

/** Export key material.
 **
 **   Requires the ExportAsPlain operation permission.
  *
  * See \ref Cmd_Export for more information.
  */
class Export: public Command
{
public:
	Export(
		HardServer &, 
		Module &, 
		const KeyIdent & );

	const char * name() const final	{ return "Export"; }

	M_KeyData	data() const	{ return reply_.reply._export.data; }
};

}
