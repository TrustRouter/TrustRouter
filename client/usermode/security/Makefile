mac: mac32 mac64

mac32: src/security.c src/security.h lib/openssl/MacOS/ia32/libcrypto.a lib/openssl/MacOS/ia32/libssl.a
	gcc -Llib/openssl/MacOS/ia32 -fPIC -c src/security.c -o security.o -arch i386
	gcc -shared -Wl,-install_name,libsecurity.dylib -Llib/openssl/MacOS/ia32 -o libsecurity.dylib  security.o -arch i386 -lcrypto -lssl
	mv libsecurity.dylib lib/MacOS/ia32
	rm security.o

mac64: src/security.c src/security.h lib/openssl/MacOS/x64/libcrypto.a lib/openssl/MacOS/x64/libssl.a
	gcc -Llib/openssl/MacOS/x64 -fPIC -c src/security.c -o security.o -arch x86_64
	gcc -shared -Wl,-install_name,libsecurity.dylib -Llib/openssl/MacOS/x64 -o libsecurity.dylib  security.o -arch x86_64 -lcrypto -lssl
	mv libsecurity.dylib lib/MacOS/x64
	rm security.o

macclean: mac32clean mac64clean
	rm security.o
	rm libsecurity.dylib

mac32clean:
	rm lib/MacOS/ia32/libsecurity.dylib

mac64clean:
	rm lib/MacOS/x64/libsecurity.dylib
	
win: win32 win64

win32: src\security.c src\security.h
	cl /MD /I lib\openssl\include /I src /TC src\security.c /link /DLL /LIBPATH lib\openssl\Windows\ia32\libeay32.lib lib\openssl\Windows\ia32\ssleay32.lib WS2_32.LIB ADVAPI32.LIB GDI32.LIB USER32.LIB /OUT:libsecurity.dll
	move libsecurity.dll lib/Windows/ia32
	del security.obj
	del libsecurity.lib
	del libsecurity.exp
	