#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#ifdef _WIN32
#define DLLExport __declspec(dllexport)
#else
#define DLLExport 
#endif

DLLExport int verify_prefix_with_cert(
    const char* CAfile, 
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    const char* cert_der,
    int cert_der_length,
    char* prefix_as_ext
);
DLLExport int verify_cert(
    const char* CAfile,
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    const char* cert_der,
    int cert_der_length
);
DLLExport int verify_signature(
    const char* cert_der,
    int cert_der_length,
    unsigned char* signature,
    const unsigned char* signed_data,
    const unsigned int signed_data_length
);