#pragma once

// These macros are defined by the bitcoin build and in
// the Thales headers. Temporarily remove the bitcoin definitions
//
#undef HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION 


// These definitions are required because the Thales C headers
// contain these C++ keywords
//
#define export _export
#define new    _new


#include <nfastapp.h>
#include <nfkm.h>
#include <nfinttypes.h>
#include <nffile.h>
#include <rqcard-applic.h>
#include <rqcard-fips.h>

#include <simplebignum.h>
#include <ncthread-upcalls.h>
#include <nfopt.h>
#include <autoversion.h>
#include <report.h>

#undef new    
#undef export 
