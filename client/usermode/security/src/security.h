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

int verify_signature(const char* certfile, unsigned char* signature, const unsigned char* signed_data, const unsigned int signed_data_length);
int verify_cert(const char* CAfile, const char* certfile, const char* untrusted_certsfile);