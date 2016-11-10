#for f in ../src/*.c; do x86_64-w64-mingw32-gcc -DPIC -DDBG_OUTPUT -DFILE_LOGGING -g -O2 -mms-bitfields -c $f; done;
for f in ../src/*.c; do x86_64-w64-mingw32-gcc -DPIC -g -O2 -mms-bitfields -c $f; done;

#x86_64-w64-mingw32-gcc -DBG_OUTPUT -DPIC -g -O2 -mms-bitfields -shared -W1,--dll -W1,--enable-auto-image-base -W1,--output-def,libp11capi.dll.def,--out-implib,libp11capi_g.dll.a -W1,--version-script -W1,libp11capi.vers -o p11capi_w64.dll p11-capi-builtin.o p11-capi-cert.o p11-capi-der.o p11-capi-key.o p11-capi.o p11-capi-object.o p11-capi-rsa.o p11-capi-session.o p11-capi-token.o p11-capi-trust.o p11-capi-util.o -lcrypt32

x86_64-w64-mingw32-gcc -DBG_OUTPUT -DPIC -g -O2 -mms-bitfields -shared -o p11capi_w64.dll p11-capi-builtin.o p11-capi-cert.o p11-capi-der.o p11-capi-key.o p11-capi.o p11-capi-object.o p11-capi-rsa.o p11-capi-session.o p11-capi-token.o p11-capi-trust.o p11-capi-util.o -lcrypt32

x86_64-w64-mingw32-objcopy --keep-global-symbols=../p11.syms "p11capi_w64.dll"
