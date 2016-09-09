#include <stdexcept>
#include "NFError.h"
#include "nfast.h"


void throwOnError( const char * str, int rc )
{
	if( rc != Status_OK )
	{
		char buff[256];
		NFast_StrError(buff, 256, static_cast<M_Status>(rc), 0);
		std::string msg = "ERROR:";
		msg += str;
		msg += ":";
		msg += buff;

		throw std::runtime_error( msg );
	}
}

void printOnError( const char * str, int rc )
{
	if( rc != Status_OK )
	{
		char buff[256];
		NFast_StrError(buff, 256, static_cast<M_Status>(rc), 0);
		std::string msg = "ERROR:";
		msg += str;
		msg += ":";
		msg += buff;

		fprintf( stderr, "%s\n", msg.c_str() );	
	}
}
