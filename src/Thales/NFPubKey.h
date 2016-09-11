#pragma once

#include "nfast.h"
#include "NFKeyIdent.h"


namespace NFast
{

class App;
class HardServer;
class KeyIdent;
class Module;


class PubKey
{
public:

	PubKey( HardServer &, Module &, const KeyIdent & id );

    PubKey( HardServer &, Module &, const KeyIdent &, M_KeyType, 
			int flags, int protectType, int recoverType );

	bool	keyExists() const	{ return keyExists_; }

	const unsigned char * data() const {	return data_; }

private:
			App	& app_;
		 KeyIdent ident_;
	unsigned char data_[65];
			 bool keyExists_;
};

}
