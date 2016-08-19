SRC_ROOT := /opt/nfast/c/ctd/examples

TARGETS := \
./nfuser/build-gcc-lib/modstate \
./nfuser/build-gcc-lib/mkdeskey \
./nfuser/build-gcc-lib/sigtest \
./nfuser/build-gcc-lib/nopclearfail \
./nfuser/build-gcc-lib/initunit \
./nfuser/build-gcc-lib/randchk \
./nfuser/build-gcc-lib/stattree \
./nfuser/build-gcc-lib/createoc-simple \
./nfuser/build-gcc-lib/kptest \
./nfuser/build-gcc-lib/des_kat \
./nfuser/build-gcc-lib/floodtest \
./nfuser/build-gcc-lib/worked-example \
./nfuser/build-gcc-lib/cryptest \
./nfuser/build-gcc-lib/blobinfo \
./nfuser/build-gcc-lib/loadcardset \
./nfuser/build-gcc-lib/gencert \
./nfuser/build-gcc-lib/ncdate \
./nfuser/build-gcc-lib/trtccert \
./nfuser/build-gcc-lib/nfkminfo \
./nfuser/build-gcc-lib/slotinfo \
./nfuser/build-gcc-lib/pollbare \
./nfuser/build-gcc-lib/nvram \
./nfuser/build-gcc-lib/enquiry \
./nfuser/build-gcc-lib/sslrectest \
./nfuser/build-gcc-lib/ncthread-test \
./nfuser/build-gcc-lib/checkmod \
./pkcs11/ckshahmac \
./pkcs11/ckcheckinst \
./pkcs11/ckinfo \
./pkcs11/cksigtest \
./pkcs11/ckrsagen \
./pkcs11/ckdes3gen \
./pkcs11/ckmechinfo \
./pkcs11/ckcmac-ctr \
./pkcs11/cklist


SRC := \
hilibs/simplebignum.c \
hilibs/seeutils.c \
hilibs/esnutils.c \
hilibs/nfutil.c \
hilibs/host-sock.c \
hilibs/connpool.c \
hilibs/nfast-ncthread.c \
hilibs/host-buffer.c \
hilibs/picky-upcalls.c \
hilibs/simplecmd.c \
nfuser/sigtest.c \
nfuser/generictest.c \
nfuser/readpp-unix.c \
nfuser/debugmalloc.c \
nfuser/simplebignum.c \
nfuser/seeutils.c \
nfuser/ncthread-test.c \
nfuser/ncthread-none.c \
nfuser/ncthread-unix.c \
nfuser/dynamic-static.c \
nfuser/randchk.c \
nfuser/modstate.c \
nfuser/cryptest.c \
nfuser/trtccert.c \
nfuser/ncdate.c \
nfuser/worked-example.c \
nfuser/ncthread-aix.c \
nfuser/pollbare.c \
nfuser/checkmod.c \
nfuser/initunit.c \
nfuser/esnutils.c \
nfuser/gencert.c \
nfuser/nfopt-time.c \
nfuser/nfutil.c \
nfuser/nopclearfail.c \
nfuser/ncthread-nt.c \
nfuser/report.c \
nfuser/host-sock.c \
nfuser/nfopt-join.c \
nfuser/ncthread-hpux.c \
nfuser/des_kat.c \
nfuser/connpool.c \
nfuser/dynamic-hpux.c \
nfuser/dynamic-nt.c \
nfuser/tokenise.c \
nfuser/getdate.c \
nfuser/ncthread-debug.c \
nfuser/nfast-ncthread.c \
nfuser/nfopt.c \
nfuser/slotinfo.c \
nfuser/nfkminfo.c \
nfuser/enquiry.c \
nfuser/sslrectest.c \
nfuser/nvram.c \
nfuser/host-buffer.c \
nfuser/ncthread-upcalls.c \
nfuser/normalmalloc.c \
nfuser/createoc-simple.c \
nfuser/loadcardset.c \
nfuser/floodtest.c \
nfuser/kptest.c \
nfuser/blobinfo.c \
nfuser/dynamic-unix.c \
nfuser/report-usage.c \
nfuser/readpp-nt.c \
nfuser/condvar.c \
nfuser/nftypes.c \
nfuser/mkdeskey.c \
nfuser/stattree.c \
nfuser/picky-upcalls.c \
nfuser/simplecmd.c \
cutils/readpp-unix.c \
cutils/debugmalloc.c \
cutils/ncthread-none.c \
cutils/ncthread-unix.c \
cutils/dynamic-static.c \
cutils/ncthread-aix.c \
cutils/nfopt-time.c \
cutils/ncthread-nt.c \
cutils/report.c \
cutils/nfopt-join.c \
cutils/ncthread-hpux.c \
cutils/dynamic-hpux.c \
cutils/dynamic-nt.c \
cutils/tokenise.c \
cutils/getdate.c \
cutils/ncthread-debug.c \
cutils/nfopt.c \
cutils/ncthread-upcalls.c \
cutils/normalmalloc.c \
cutils/dynamic-unix.c \
cutils/report-usage.c \
cutils/readpp-nt.c \
cutils/condvar.c \
cutils/nftypes.c \
pkcs11/ckmechinfo.c \
pkcs11/cklist.c \
pkcs11/ckerrcode.c \
pkcs11/ckshahmac.c \
pkcs11/ckinfo.c \
pkcs11/ckcheckinst.c \
pkcs11/ckcmac-ctr.c \
pkcs11/ckreadpin.c \
pkcs11/ckutilprint.c \
pkcs11/pthreadthread.c \
pkcs11/ckdes3gen.c \
pkcs11/cktestutil.c \
pkcs11/ckrsagen.c \
pkcs11/ckmutex-pthread.c \
pkcs11/ckcrypt.c \
pkcs11/ckutil.c \
pkcs11/cknfkmid.c \
pkcs11/cksigtest.c

YSRC := cutils/getdate.y

HDR := \
hilibs/host-sock.h \
hilibs/nfast-ncthread.h \
hilibs/nfutil.h \
hilibs/picky-upcalls.h \
hilibs/simplebignum.h \
hilibs/connpool.h \
hilibs/esnutils.h \
hilibs/simplecmd.h \
hilibs/host-buffer.h \
nfuser/generictest.h \
nfuser/debugmalloc.h \
nfuser/nftypes.h \
nfuser/dynamic-unix.h \
nfuser/host-sock.h \
nfuser/autoversion.h \
nfuser/nfast-ncthread.h \
nfuser/nfutil.h \
nfuser/dynamic-hpux.h \
nfuser/dynamic-nt.h \
nfuser/ncthread.h \
nfuser/picky-upcalls.h \
nfuser/dynamic-sys.h \
nfuser/simplebignum.h \
nfuser/report.h \
nfuser/ncthread-nt.h \
nfuser/nfopt.h \
nfuser/connpool.h \
nfuser/ncthread-unix.h \
nfuser/esnutils.h \
nfuser/simplecmd.h \
nfuser/ncthread-hpux.h \
nfuser/condvar.h \
nfuser/ncthread-none.h \
nfuser/ncthread-sys.h \
nfuser/readpp.h \
nfuser/host-buffer.h \
nfuser/ncthread-aix.h \
nfuser/getdate.h \
nfuser/dynamic.h \
nfuser/ncthread-upcalls.h \
nfuser/tokenise.h \
nfuser/nfopt-join.h \
cutils/debugmalloc.h \
cutils/nftypes.h \
cutils/getdate.y \
cutils/dynamic-unix.h \
cutils/dynamic-hpux.h \
cutils/dynamic-nt.h \
cutils/ncthread.h \
cutils/dynamic-sys.h \
cutils/report.h \
cutils/ncthread-nt.h \
cutils/nfopt.h \
cutils/ncthread-unix.h \
cutils/ncthread-hpux.h \
cutils/condvar.h \
cutils/ncthread-none.h \
cutils/ncthread-sys.h \
cutils/readpp.h \
cutils/ncthread-aix.h \
cutils/getdate.h \
cutils/dynamic.h \
cutils/ncthread-upcalls.h \
cutils/tokenise.h \
cutils/nfopt-join.h \
pkcs11/ckutil.h \
pkcs11/autoversion.h \
pkcs11/ckcmac-ctr.h \
pkcs11/cktestutil.h \
pkcs11/kcdsagroup.h \
pkcs11/ecparams.h \
pkcs11/ckmutex.h \
pkcs11/ckerrcode.h \
pkcs11/examplethread.h \
pkcs11/dsagroup.h

MSRC := \
nfuser/build-gcc-lib/Makefile-examples \
nfuser/platform-versions.make \
cutils/platform-versions.make

##############################################################################

all: copyFiles
	cd nfuser/build-gcc-lib/; make -f Makefile-examples
	cd pkcs11/; make -f Makefile-Unix

clean:
	find . -name '*.o' -exec rm {} \;
	rm -f $(TARGETS)
	rm -f $(MSRC) $(SRC) $(HDR) $(YSRC)
	rm -rf hilibs cutils nfuser

##############################################################################

copyFiles: dirs $(SRC) $(HDR) $(YSRC) $(MSRC)

hilibs/%.c: $(SRC_ROOT)/hilibs/%.c
	cp $< $@

hilibs/%.h: $(SRC_ROOT)/hilibs/%.h
	cp $< $@

pkcs11/%.c: $(SRC_ROOT)/pkcs11/%.c
	cp $< $@

pkcs11/%.h: $(SRC_ROOT)/pkcs11/%.h
	cp $< $@

nfuser/%.c: $(SRC_ROOT)/nfuser/%.c
	cp $< $@

nfuser/%.h: $(SRC_ROOT)/nfuser/%.h
	cp $< $@

cutils/%.c: $(SRC_ROOT)/cutils/%.c
	cp $< $@

cutils/%.h: $(SRC_ROOT)/cutils/%.h
	cp $< $@

cutils/%.y: $(SRC_ROOT)/cutils/%.y
	cp $< $@

$(MSRC):
	cp $(SRC_ROOT)/$@ $@

##############################################################################

dirs:
	@mkdir -p hilibs
	@mkdir -p nfuser/build-gcc-lib
	@mkdir -p cutils


