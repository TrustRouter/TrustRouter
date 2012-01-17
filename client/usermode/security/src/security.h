#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int rsa_signed_with_cert(const char* certfile, const char* sigfile, const char* unencrypted, const int unencrypted_length);
int verify_cert_from_path(const char* CAfile, const char* certfile, const char* untrusted_certsfile);