#pragma once


#include "nfast.h"
#include <string>


namespace NFast
{

class KeyIdent
{
public:
	KeyIdent( const char * appName, const char * ident );
	KeyIdent( const KeyIdent & );
	~KeyIdent();

	KeyIdent & operator = ( const KeyIdent & );

	const NFKM_KeyIdent & data() const { return keyIdent_; }

	const char * appName() const { return appName_; }
	const char * ident() const { return ident_; }

private:
	NFKM_KeyIdent keyIdent_;
	char * appName_;
	char * ident_;
};

}
