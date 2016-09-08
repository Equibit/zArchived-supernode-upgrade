#pragma once

#include "nfast.h"

namespace NFast
{

class CardLoadingLib;
class SecurityWorld;


class Module
{
public:
	Module( SecurityWorld &, CardLoadingLib & );
	Module( SecurityWorld &, CardLoadingLib &, M_ModuleID );

	~Module();

	M_ModuleID  	  id() const			{ return id_; }
	NFKM_CardSetIdent cardSetHash() const	{ return cardSetHash_; }
	NFKM_CardSet 	* cardSet()				{ return cardSet_; }
	SecurityWorld 	& world()				{ return world_; }
    CardLoadingLib  & cardLoadingLib()		{ return cardLoadingLib_; }
   NFKM_ModuleInfo  * & info()				{ return moduleInfo_; }
			  M_KeyID cardSetId()           { return cardSetId_; }

private:
	void init();

	 SecurityWorld & world_;
    CardLoadingLib & cardLoadingLib_;
		  M_ModuleID id_;
			 M_KeyID cardSetId_;
   NFKM_ModuleInfo * moduleInfo_;
	  NFKM_CardSet * cardSet_;
   NFKM_CardSetIdent cardSetHash_;
};

}
