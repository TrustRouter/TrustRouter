// linked against static self-compiled version of openssl-libs with enable-rfc3779 flag

#include "security.h"

static X509 *load_cert_der(int cert_der_length, const char* cert_der);
static STACK_OF(X509) *load_certs_der(
    int cert_der_count,
    int cert_der_length,
    const char* certs_der
);
static STACK_OF(X509) *get_verified_chain(
    int CA_der_count,
    int CA_der_length,
    const char* CAs_der,
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    int cert_der_length,
    const char* cert_der
);

// verify if prefix is part of the resources listed in cert
// CA and untrusted are needed, because the resources in cert could be inherited
// prefix_as_ext is the text-representation of an ip-address block like you would specify in an extension file
// when creating a certificate, e.g. IPv6:2001:0638::/32
int verify_prefix_with_cert(
    int CA_der_count,
    int CA_der_length,
    const char* CAs_der, 
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    int cert_der_length,
    const char* cert_der,
    char* prefix_as_ext
) 
{
    X509_EXTENSION *prefix_ext;
    IPAddrBlocks *prefix_blocks = NULL;
    STACK_OF(X509) *chain = NULL;

    int allow_inheritance = 0; // router prefix cannot inherit
    int ret = 0;
    if ((prefix_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_sbgp_ipAddrBlock, prefix_as_ext)) == NULL){
        ret = -1;
        goto end;
    }
    prefix_blocks = (IPAddrBlocks *) X509V3_EXT_d2i(prefix_ext);
    X509_EXTENSION_free(prefix_ext);

    chain = get_verified_chain(
        CA_der_count,
        CA_der_length,
        CAs_der,
        untrusted_der_count,
        untrusted_der_length,
        untrusted_der,
        cert_der_length,
        cert_der
    );

    if (chain == NULL) {
        ret = 0;
    } else {
        ret = v3_addr_validate_resource_set(chain, prefix_blocks, allow_inheritance);
    }
end:
    if (prefix_blocks != NULL) sk_IPAddressFamily_pop_free(prefix_blocks, IPAddressFamily_free);
    if (chain != NULL) sk_X509_pop_free(chain, X509_free);

    return ret;
}


int verify_cert(
    int CA_der_count,
    int CA_der_length,
    const char* CAs_der,
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    int cert_der_length,
    const char* cert_der
)     
{     
    int ret = 0;     
    STACK_OF(X509) *chain = NULL;
    chain = get_verified_chain(
        CA_der_count,
        CA_der_length,
        CAs_der,
        untrusted_der_count,
        untrusted_der_length,
        untrusted_der,
        cert_der_length,
        cert_der
    );

    if (chain == NULL) {
        ret = 0;
    } else {
        ret = 1;
    }
    if (chain != NULL) sk_X509_pop_free(chain, X509_free);
    
    return ret;     
}

static STACK_OF(X509) *get_verified_chain(
    int CA_der_count,
    int CA_der_length,
    const char* CAs_der,
    int untrusted_der_count,
    int untrusted_der_length,
    const char* untrusted_der,
    int cert_der_length,
    const char* cert_der
)
{
    X509_STORE_CTX store_ctx;
    X509_LOOKUP *lookup = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *untrusted = NULL;
    STACK_OF(X509) *CAs = NULL;
    STACK_OF(X509) *chain = NULL;

    OpenSSL_add_all_algorithms();

    if (CA_der_count > 0) {
        CAs = (STACK_OF(X509)*) load_certs_der(
            CA_der_count,
            CA_der_length,
            CAs_der
        );
    }

    if (untrusted_der_count > 0) {
        untrusted = (STACK_OF(X509)*) load_certs_der(
            untrusted_der_count,
            untrusted_der_length,
            untrusted_der
        );
    }

    cert = d2i_X509(NULL, (const unsigned char **) &cert_der, cert_der_length);
    if (cert == NULL) {
        chain = NULL;
        goto end;
    }

    X509_STORE_CTX_init(&store_ctx, NULL, cert, untrusted);
    X509_STORE_CTX_trusted_stack(&store_ctx, CAs);

    if (X509_verify_cert(&store_ctx) <= 0) {
        // no chain for the certificate can be constructed
        chain = NULL;
        X509_STORE_CTX_cleanup(&store_ctx);
        goto end;        
    } else {
        chain = X509_STORE_CTX_get1_chain(&store_ctx);
    }
    X509_STORE_CTX_cleanup(&store_ctx);

end:
    if (cert != NULL) X509_free(cert);
    if (untrusted != NULL) sk_X509_pop_free(untrusted, X509_free);
    if (CAs != NULL) sk_X509_pop_free(CAs, X509_free);
    EVP_cleanup();
    return chain;
}

int verify_signature(
    int cert_der_length,
    const char* cert_der,
    unsigned char* signature,
    const unsigned int signed_data_length,
    const unsigned char* signed_data
)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    int keysize;
    int ret = 0;
    unsigned char digest[SHA_DIGEST_LENGTH];

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();

    cert = d2i_X509(NULL, (const unsigned char **) &cert_der, cert_der_length);
    if (cert != NULL) {
        pkey = X509_get_pubkey(cert);
        X509_free(cert);
    }
    if (!pkey) {
        ret = -1;
        goto end;
    }
    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!rsa) {
        ret = -1;
        goto end;
    }

    keysize = RSA_size(rsa);
    SHA1(signed_data, signed_data_length, (unsigned char *) &digest);
    ret = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, signature, keysize, rsa);

end:
    RSA_free(rsa);
    EVP_cleanup();
    return ret;
}

static X509 *load_cert_der(int cert_der_length, const char* cert_der)
{
    X509 *cert = d2i_X509(NULL, (const unsigned char **) &cert_der, cert_der_length);
    return cert;
}

static STACK_OF(X509) *load_certs_der(
    int cert_der_count,
    int cert_der_length,
    const char* certs_der)
{
    STACK_OF(X509) *untrusted = NULL;
    X509 *cert = NULL;
    int i = 0;
    if (!(untrusted = sk_X509_new_null())) return untrusted;

    while (i < cert_der_count) {
        cert = (X509 *) load_cert_der(cert_der_length, (char *) &certs_der[i * cert_der_length]);
        sk_X509_push(untrusted, cert);
        i++;
    }
    return untrusted;
}