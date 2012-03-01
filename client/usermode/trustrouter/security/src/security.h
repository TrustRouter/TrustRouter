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
    int CA_der_count,
    int CA_der_length,
    const char* CAs_der, 
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    int cert_der_length,
    const char* cert_der,
    char* prefix_as_ext
);
DLLExport int verify_cert(
    int CA_der_count,
    int CA_der_length,
    const char* CAs_der,
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    int cert_der_length,
    const char* cert_der
);
DLLExport int verify_signature(
    int cert_der_length,
    const char* cert_der,
    unsigned char* signature,
    const unsigned int signed_data_length,
    const unsigned char* signed_data
);