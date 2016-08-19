
- The nShield C source sample programs were extracted from the tar files 
  contained in the ISO file CipherTools-linux64-dev-12.10.01.iso. 

- They are contained in the tar file linux/libc6_11/amd64/nfast/ctd/agg.tar.

- After tar extraction, the files will be located in /opt/nfast/c/ctd/examples.

- See /opt/nfast/c/ctd/examples/nfuser/EXAMPLES.README for a description of the
  samples.

- Use the Makefile to build the examples. The build will fail unless the 
  following changes are made to the local copy of pkcs11/Makefile-Unix.


47,48c47
< # CKLIB=    -L$(PKCS11_LIB)  -lcknfast  $(PKCS11_LIB)/libcutils_thr.a
< CKLIB=    -L$(PKCS11_LIB)  -lcknfast  
---
> CKLIB=    -L$(PKCS11_LIB)  -lcknfast  $(PKCS11_LIB)/libcutils_thr.a
57c56
< # RPATH= -R$(PKCS11_LIB)
---
> RPATH= -R$(PKCS11_LIB)
60c59
< RPATH= -Xlinker -rpath -Xlinker $(PKCS11_LIB)
---
> # RPATH= -Xlinker -rpath -Xlinker $(PKCS11_LIB)
88,91c87,88
< # LDLIBS=		$(CKLIB) $(EXAMPLESLIB) -lsocket
< LDLIBS=		$(CKLIB) $(EXAMPLESLIB) 
< # LDLIBS_THREADED= $(CKLIB) $(EXAMPLESLIB) -lsocket -lpthread
< LDLIBS_THREADED= $(CKLIB) $(EXAMPLESLIB) -lpthread
---
> LDLIBS=		$(CKLIB) $(EXAMPLESLIB) -lsocket
> LDLIBS_THREADED= $(CKLIB) $(EXAMPLESLIB) -lsocket -lpthread

