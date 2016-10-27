#
# NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE
#
# The build of these files depends on the Thales nCore product installation at /opt/nfast/c/ctd/gcc
#
# NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE
#

TARGET := libnfast.so 

OBJS := \
NFApp.o \
NFCardLoadingLib.o \
NFCommand.o \
NFError.o \
NFFindKey.o \
NFHardServer.o \
NFKeyIdent.o \
NFModule.o \
NFPubKey.o \
NFSecurityWorld.o \
interface.o \
get_mac.o


THALES_OBJS := \
simplebignum.o \
nfutil.o \
ncthread-upcalls.o \
ncthread-unix.o \
normalmalloc.o


CFLAGS := \
-I/opt/nfast/c/ctd/gcc/include/cutils \
-I/opt/nfast/c/ctd/gcc/include/hilibs \
-I/opt/nfast/c/ctd/gcc/include/hwcrhk \
-I/opt/nfast/c/ctd/gcc/include/nflibs \
-I/opt/nfast/c/ctd/gcc/include/nflog \
-I/opt/nfast/c/ctd/gcc/include/pkcs11 \
-I/opt/nfast/c/ctd/examples/cutils \
-I/opt/nfast/c/ctd/examples/hilibs \
-I/opt/nfast/c/ctd/examples/nfuser \
-I/opt/nfast/c/ctd/examples/pkcs11 \
-I/opt/nfast/c/ctd/gcc/include/sworld \
-g -O2  -Wall -Wwrite-strings -Wsign-compare -Wclobbered -Wempty-body -Wignored-qualifiers -Wuninitialized -D_FORTIFY_SOURCE=2 -Wno-format-zero-length -D_GNU_SOURCE -Wno-nonnull -Werror -O2 -fPIC -Wno-nonnull

CONLY_FLAGS := -Wold-style-declaration -Wstrict-prototypes -Wmissing-prototypes 

CPPFLAGS := \
-std=c++14 \
$(CFLAGS)

CPP := g++ $(CFLAGS)
CC  := gcc $(CFLAGS)

LIBS := \
/opt/nfast/c/ctd/gcc/lib/librqcard.a \
/opt/nfast/c/ctd/gcc/lib/libnfkm.a \
/opt/nfast/c/ctd/gcc/lib/libnfstub.a \
/opt/nfast/c/ctd/gcc/lib/libnflog.a \
/opt/nfast/c/ctd/gcc/lib/libcutils.a \
-lpthread -lrt -lnsl


##################################################

all: $(TARGET)

clean:
	rm -f *.o 
	rm -f libnfast.so
	rm -f $(TARGET)
	rm -f core

##################################################

libnfast.so: $(OBJS) $(THALES_OBJS)
	$(CPP) -shared -o $@ $(OBJS) $(THALES_OBJS) $(LIBS)

NFApp.o: NFApp.cpp NFApp.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

NFCardLoadingLib.o: NFCardLoadingLib.cpp NFCardLoadingLib.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

NFCommand.o: NFCommand.cpp NFCommand.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

NFError.o: NFError.cpp NFError.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<
 
NFHardServer.o: NFHardServer.cpp NFHardServer.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<
 
NFModule.o: NFModule.cpp NFModule.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

NFSecurityWorld.o: NFSecurityWorld.cpp NFSecurityWorld.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

NFFindKey.o: NFFindKey.cpp NFFindKey.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

NFKeyIdent.o: NFKeyIdent.cpp NFKeyIdent.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

NFPubKey.o: NFPubKey.cpp NFPubKey.h
	$(CPP) $(CPPFLAGS) -c -o $@ $<

interface.o: interface.cpp
	$(CPP) $(CPPFLAGS) -c -o $@ $<

get_mac.o: get_mac.cpp
	$(CPP) $(CPPFLAGS) -c -o $@ $<

#################################################
# Source provided by Thales
#################################################

simplebignum.o: /opt/nfast/c/ctd/examples/nfuser/simplebignum.c
	$(CC) -c -o $@ $<

nfutil.o: /opt/nfast/c/ctd/examples/nfuser/nfutil.c
	$(CC) -c -o $@ $<

ncthread-upcalls.o: /opt/nfast/c/ctd/examples/cutils/ncthread-upcalls.c
	$(CC) -c -o $@ $<

ncthread-unix.o: /opt/nfast/c/ctd/examples/cutils/ncthread-unix.c
	$(CC) -c -o $@ $<

normalmalloc.o: /opt/nfast/c/ctd/examples/nfuser/normalmalloc.c
	$(CC) -c -o $@ $<
