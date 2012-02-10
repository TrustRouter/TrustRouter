// linked against static self-compiled version of openssl-libs with enable-rfc3779 flag

#include "security.h"

static X509 *load_cert(const char *file);
static STACK_OF(X509) *load_certs(const char *file);
static STACK_OF(X509) *get_verified_chain(const char* CAfile, const char* untrusted_certsfile, const char* certfile)
;

// verify if prefix is part of the resources listed in cert
// CA and untrusted are needed, because the resources in cert could be inherited
// prefix_as_ext is the text-representation of an ip-address block like you would specify in an extension file
// when creating a certificate, e.g. IPv6:2001:0638::/32
int verify_prefix_with_cert(const char* CAfile, const char* untrusted_certsfile, const char* certfile, char* prefix_as_ext) 
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
    chain = get_verified_chain(CAfile, untrusted_certsfile, certfile);
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


int verify_cert(const char* CAfile, const char* untrusted_certsfile, const char* certfile)     
{     
    int ret = 0;     
    STACK_OF(X509) *chain = NULL;

    chain = get_verified_chain(CAfile, untrusted_certsfile, certfile);
    if (chain == NULL) {
        ret = 0;
    } else {
        ret = 1;
    }
    if (chain != NULL) sk_X509_pop_free(chain, X509_free);
    
    return ret;     
}

static STACK_OF(X509) *get_verified_chain(const char* CAfile, const char* untrusted_certsfile, const char* certfile)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX store_ctx;
    X509_LOOKUP *lookup = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *untrusted = NULL;
    STACK_OF(X509) *chain = NULL;

    OpenSSL_add_all_algorithms();

    if (untrusted_certsfile) {
        untrusted = (STACK_OF(X509)*) load_certs(untrusted_certsfile);
    }

    store = X509_STORE_new();
    if (store == NULL) {
        chain = NULL;
        goto end;
    }   

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        chain = NULL;
        goto end;        
    }

    if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
        chain = NULL;
        goto end;        
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
        chain = NULL;
        goto end;
    }

    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    cert = load_cert(certfile);
    if (cert == NULL) {
        chain = NULL;
        goto end;
    }
    X509_STORE_set_flags(store, 0);
    X509_STORE_CTX_init(&store_ctx, store, cert, untrusted);

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
    if (store != NULL) X509_STORE_free(store);
    if (untrusted != NULL) sk_X509_pop_free(untrusted, X509_free);
    EVP_cleanup();
    return chain;
}

int verify_signature(const char* certfile, unsigned char* signature, const unsigned char* signed_data, const unsigned int signed_data_length)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    int keysize;
    int ret = 0;
    const EVP_MD *digest_algorithm;
    EVP_MD_CTX *ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length;
    int rsa_out_length;
    unsigned char *rsa_out = NULL;
    // defined in rfc3447 EMSA-PKCS1-v1_5-ENCODE
    const unsigned int sha1_digest_info_length = 15;
    const char sha1_digest_info[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
    int i;

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();

    cert = load_cert(certfile);
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
    digest_algorithm = EVP_sha1();
    ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, digest_algorithm, NULL);
    EVP_DigestUpdate(ctx, signed_data, signed_data_length);
    EVP_DigestFinal_ex(ctx, digest, &digest_length);
    EVP_MD_CTX_cleanup(ctx);

    rsa_out = OPENSSL_malloc(keysize);
    rsa_out_length = RSA_public_decrypt(keysize,signature,rsa_out,rsa,RSA_PKCS1_PADDING);

    if (rsa_out_length != (digest_length + sha1_digest_info_length)) {
        ret = 0;
    } else {
        ret = 1;
        for (i = 0; i < sha1_digest_info_length; i++) {
            if (sha1_digest_info[i] != rsa_out[i]) {
                ret = 0;
            }
        }
        for (i = sha1_digest_info_length; i < rsa_out_length; i++) {
            if (rsa_out[i] != digest[i - sha1_digest_info_length]) {
                ret = 0;
            }
        }
    }
end:
    if (rsa_out) OPENSSL_free(rsa_out);
    RSA_free(rsa);
    EVP_cleanup();
    return ret;
}

static X509 *load_cert(const char *file)
{
    X509 *x = NULL;
    BIO *cert;

    if ((cert = BIO_new(BIO_s_file())) == NULL) goto end;
    if (BIO_read_filename(cert,file) <= 0) goto end;
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);

end:
    if (cert != NULL) BIO_free(cert);
    return x;
}

static STACK_OF(X509) *load_certs(const char *certfile)
{
    STACK_OF(X509_INFO) *sk = NULL;
    STACK_OF(X509) *stack = NULL, *ret = NULL;
    BIO *in = NULL;
    X509_INFO *xi;

    if (!(stack = sk_X509_new_null())) goto end;
    if (!(in = BIO_new_file(certfile, "r"))) goto end;
    /* This loads from a file, a stack of x509/crl/pkey sets */
    if (!(sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL))) goto end;

    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk)) {
        xi = sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack,xi->x509);
            xi->x509 = NULL;
        }
        X509_INFO_free(xi);
    }
    if (!sk_X509_num(stack)) {
        sk_X509_free(stack);
        goto end;
    }
    ret = stack;
end:
    BIO_free(in);
    sk_X509_INFO_free(sk);
    return ret;
}