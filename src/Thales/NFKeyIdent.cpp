#include "NFKeyIdent.h"
#include <string>
#include <stdexcept>


namespace NFast
{

namespace
{

bool verifyName( const std::string & id )
{
	if( id.size() == 0 )
		return false;

	std::string::const_iterator i = id.begin();
	std::string::const_iterator e = id.end();

	while( i != e )
	{
		if( strchr( NFKM_KEYIDENT_CHARS, *i ) == NULL )
			return false;

		++i;
	}

	return true;
}

}


KeyIdent::KeyIdent( const char * appName, const char * ident ):
	appName_(strdup(appName)),
	ident_(strdup(ident))
{
	if( !appName_ )
	{
		if(ident_ )
			free(ident_ );
		throw std::bad_alloc();
	}
	if( !ident_ )
	{
		free(appName_);
		throw std::bad_alloc();
	}
	keyIdent_.appname = appName_;
	keyIdent_.ident = ident_;	

	if(!verifyName( appName ))
	{
		free(ident_ );
		free(appName_);
		std::string msg = "Invalid application name [";
		msg += appName;
		msg += "]";

		throw std::runtime_error( msg );
	}
	if(!verifyName( ident ))
	{
		free(ident_ );
		free(appName_);
		std::string msg = "Invalid key identifier [";
		msg += ident;
		msg += "]";

		throw std::runtime_error( msg );
	}
}

KeyIdent::KeyIdent( const KeyIdent & k ):
	appName_(strdup(k.appName_)),
	ident_(strdup(k.ident_))
{
	if( !appName_ )
	{
		if(ident_ )
			free(ident_ );
		throw std::bad_alloc();
	}
	if( !ident_ )
	{
		free(appName_);
		throw std::bad_alloc();
	}
	keyIdent_.appname = appName_;
	keyIdent_.ident = ident_;	

	// no need to verify. The source KeyIdent already did so
}

KeyIdent & KeyIdent::operator = ( const KeyIdent & k )
{
	free(appName_ );
	free(ident_ );

	appName_ = strdup(k.appName_);

	if( !appName_ )
		throw std::bad_alloc();

	ident_ = strdup(k.ident_);
	if( !ident_ )
	{
		free(appName_);
		throw std::bad_alloc();
	}
	keyIdent_.appname = appName_;
	keyIdent_.ident = ident_;	

	// no need to verify. The source KeyIdent already did so

	return *this;
}

KeyIdent::~KeyIdent()
{
	if( appName_ )
		free(appName_ );
	if(ident_ )
		free(ident_ );
}

}
