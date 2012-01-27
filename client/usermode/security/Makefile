mac: mac32 mac64

mac32: src/security.c src/security.h lib/openssl/MacOS/ia32/libcrypto.a lib/openssl/MacOS/ia32/libssl.a
	gcc -Isrc -Ilib/openssl/include -Llib/openssl/MacOS/ia32 -fPIC -c src/security.c -o security.o -m32
	gcc -shared -fPIC -Wl,-install_name,libsecurity.dylib -Isrc -Ilib/openssl/include -Llib/openssl/MacOS/ia32 -o libsecurity.dylib  security.o -m32 -lcrypto -lssl
	mv libsecurity.dylib lib/MacOS/ia32
	rm security.o

mac64: src/security.c src/security.h lib/openssl/MacOS/x64/libcrypto.a lib/openssl/MacOS/x64/libssl.a
	gcc -Isrc -Ilib/openssl/include -Llib/openssl/MacOS/x64 -fPIC -c src/security.c -o security.o -m64
	gcc -Isrc -Ilib/openssl/include -shared -fPIC -Wl,-install_name,libsecurity.dylib -Llib/openssl/MacOS/x64 -o libsecurity.dylib  security.o -m64 -lcrypto -lssl
	mv libsecurity.dylib lib/MacOS/x64
	rm security.o

macclean: mac32clean mac64clean
	rm security.o
	rm libsecurity.dylib

mac32clean:
	rm lib/MacOS/ia32/libsecurity.dylib

mac64clean:
	rm lib/MacOS/x64/libsecurity.dylib

lin: lin32 lin64

lin32: src/security.c src/security.h lib/openssl/Linux/ia32/libcrypto.a lib/openssl/Linux/ia32/libssl.a
	gcc -Wall -fPIC -c src/security.c -Isrc -Ilib/openssl/include -m32
	gcc -shared -fPIC -Llib/openssl/Linux/ia32 -Wl,-Bsymbolic -o libsecurity.so security.o -m32 -lcrypto -lssl
	mv libsecurity.so lib/Linux/ia32
	rm security.o

lin64: src/security.c src/security.h lib/openssl/Linux/x64/libcrypto.a lib/openssl/Linux/x64/libssl.a
	gcc -Wall -fPIC -c src/security.c -Isrc -Ilib/openssl/include -m64
	gcc -shared -fPIC -Llib/openssl/Linux/x64 -Wl,-Bsymbolic -o libsecurity.so security.o -m64 -lcrypto -lssl
	mv libsecurity.so lib/Linux/x64
	rm security.o

linclean: lin32clean lin64clean
	rm security.o
	rm libsecurity.so

lin32clean:
	rm lib/Linux/ia32/libsecurity.so

lin64clean:
	rm lib/Linux/x64/libsecurity.so
	
win: win32 win64

win32: src\security.c src\security.h
	cl /MD /I lib\openssl\include /I src /TC src\security.c /link /DLL /LIBPATH lib\openssl\Windows\ia32\libeay32.lib lib\openssl\Windows\ia32\ssleay32.lib WS2_32.LIB ADVAPI32.LIB GDI32.LIB USER32.LIB /OUT:libsecurity.dll
	move libsecurity.dll lib/Windows/ia32
	del security.obj
	del libsecurity.lib
	del libsecurity.exp
	
win64: src\security.c src\security.h
	cl /MD /I lib\openssl\include /I src /TC src\security.c /link /DLL /LIBPATH lib\openssl\Windows\x64\libeay32.lib lib\openssl\Windows\x64\ssleay32.lib WS2_32.LIB ADVAPI32.LIB GDI32.LIB USER32.LIB /OUT:libsecurity.dll
	move libsecurity.dll lib/Windows/x64
	del security.obj
	del libsecurity.lib
	del libsecurity.exp
