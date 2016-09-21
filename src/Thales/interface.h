#pragma once

#include <vector>


// This file defines the functions and constants that provide access to the NFast
// functionality
//

namespace NFast
{

class App;
class SecurityWorld;
class HardServer;
class CardLoadingLib;
class Module;


// Initialize the NFast library
//
bool init(  
			   App * & appPtr,
	 SecurityWorld * & swPtr,
		HardServer * & hsPtr,
	CardLoadingLib * & cllPtr,
			Module * & mdPtr );


// Terminate the NFast library
//
void terminate(  
			   App * & appPtr,
	 SecurityWorld * & swPtr,
		HardServer * & hsPtr,
	CardLoadingLib * & cllPtr,
			Module * & mdPtr );

const size_t	MAC_SIZE = 6;

const size_t	HSMID_SIZE= MAC_SIZE + 			// MAC (Media Access Control) size
							sizeof(pid_t) + 	// Size of process ID
							sizeof(pid_t) + 	// Size of thread ID
							sizeof(time_t) + 	// Size of timespec::tv_sec
							sizeof(long);		// Size of timespec::tv_nsec

const size_t	SHA1_SIZE			= 20;
const size_t	IDENT_SIZE 			= 2*SHA1_SIZE + 1;
const size_t	PUBKEY_DATA_SIZE 	= 65;

// Generate a new key pair
//
bool generateKeyPair( 
	   HardServer & hs,
		   Module & module,
	unsigned char * pubkeydata, 
	         char * HSMid );

bool sign(
				  HardServer & hsPtr,
					  Module & module,
		   const std::string & hsmID,
		 const unsigned char * in,
		                size_t inSize,
  std::vector<unsigned char> & signature );

}

