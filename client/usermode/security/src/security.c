// linked against static self-compiled version of openssl-libs with enable-rfc3779 flag
// gcc -I/usr/local/ssl/include -L. -fPIC -c security.c -lcrypto -lssl -o security.o -arch i386
// gcc -shared -Wl,-install_name,libsecurity.1.1.dylib -I/usr/local/ssl/include -L. -o libsecurity.1.1.dylib  security.o -arch i386 -lcrypto -lssl

/* parts adapted from openssl apps/verify.c and apps/rsautl.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "security.h"

static X509 *load_cert(const char *file);
static int check(X509_STORE *ctx, const char *file, STACK_OF(X509) *uchain);
static STACK_OF(X509) *load_untrusted(const char *file);

int rsa_signed_with_cert(const char* certfile, const char* sigfile, const char* unencrypted, const int unencrypted_length)
{

    BIO *in = NULL, *out = NULL;
    X509 *cert;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    unsigned char *rsa_in = NULL, *rsa_out = NULL, pad;
    int rsa_inlen, rsa_outlen = 0;
    int keysize;
    int ret = 0;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    pad = RSA_PKCS1_PADDING;

    cert = load_cert(certfile);
    if(cert) {
        pkey = X509_get_pubkey(cert);
        X509_free(cert);
    }

    if(!pkey) {
        ret = -1;
        return ret;
    }
    
    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);

    if(!rsa) {
        RSA_free(rsa);
        BIO_free(in);
        BIO_free_all(out);
        if(rsa_in) OPENSSL_free(rsa_in);
        if(rsa_out) OPENSSL_free(rsa_out);
        ret = -1;
        return ret;
    }

    if(!(in = BIO_new_file(sigfile, "rb"))) {
        RSA_free(rsa);
        BIO_free(in);
        BIO_free_all(out);
        if(rsa_in) OPENSSL_free(rsa_in);
        if(rsa_out) OPENSSL_free(rsa_out);
        ret = -1;
        return ret;     
    }

    keysize = RSA_size(rsa);
    rsa_in = OPENSSL_malloc(keysize * 2);
    rsa_out = OPENSSL_malloc(keysize);
    pad = RSA_PKCS1_PADDING;

    /* Read the input data */
    rsa_inlen = BIO_read(in, rsa_in, keysize * 2);
    if(rsa_inlen <= 0) {
        ret = -1;
        return ret;
    }

    rsa_outlen  = RSA_public_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);

    if (rsa_outlen <= 0) {
        RSA_free(rsa);
        BIO_free(in);
        BIO_free_all(out);
        if(rsa_in) OPENSSL_free(rsa_in);
        if(rsa_out) OPENSSL_free(rsa_out);
        ret = 0;
        return ret;
    }

    if (rsa_outlen != unencrypted_length) {
        RSA_free(rsa);
        BIO_free(in);
        BIO_free_all(out);
        if(rsa_in) OPENSSL_free(rsa_in);
        if(rsa_out) OPENSSL_free(rsa_out);
        ret = 0;
        return ret;
    }

    ret = 1;
    int i;
    for (i = 0; i < rsa_outlen; i++) {
        if (rsa_out[i] != unencrypted[i]) {
            ret = 0;
        }
    }
    RSA_free(rsa);
    BIO_free(in);
    BIO_free_all(out);
    if(rsa_in) OPENSSL_free(rsa_in);
    if(rsa_out) OPENSSL_free(rsa_out);
    return ret;
}

int verify_cert_from_path(const char* CAfile, const char* certfile, const char* untrusted_certsfile)
{
    // printf("cert: %s\t untrusted: %s\t CA: %s\n", certfile, untrusted_certsfile, CAfile);
    int ret = 0;
    X509_STORE *cert_ctx = NULL;
    X509_LOOKUP *lookup = NULL;
    STACK_OF(X509) *untrusted = NULL;

    cert_ctx=X509_STORE_new();
    if (cert_ctx == NULL) goto end;

    OpenSSL_add_all_algorithms();

    lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_file());
    if (lookup == NULL)
        goto end;

    if(!X509_LOOKUP_load_file(lookup,CAfile,X509_FILETYPE_PEM))
        goto end;

    lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        goto end;

    X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);

    if(untrusted_certsfile)
        {
        untrusted = (STACK_OF(X509)*) load_untrusted(untrusted_certsfile);
        if(!untrusted)
            goto end;
        }

    ret = check(cert_ctx, certfile, untrusted);
end:
    if (cert_ctx != NULL) X509_STORE_free(cert_ctx);
    sk_X509_pop_free(untrusted, X509_free);
    return ret;
}

static X509 *load_cert(const char *file)
{
    X509 *x = NULL;
    BIO *cert;

    if ((cert = BIO_new(BIO_s_file())) == NULL)
        goto end;

    if (BIO_read_filename(cert,file) <= 0)
        goto end;

    x=PEM_read_bio_X509_AUX(cert,NULL, NULL, NULL);
end:
    if (cert != NULL) BIO_free(cert);
    return(x);
}

static STACK_OF(X509) *load_untrusted(const char *certfile)
{
    STACK_OF(X509_INFO) *sk = NULL;
    STACK_OF(X509) *stack = NULL, *ret = NULL;
    BIO *in = NULL;
    X509_INFO *xi;

    if(!(stack = sk_X509_new_null())) {
        goto end;
    }

    if(!(in = BIO_new_file(certfile, "r"))) {
        goto end;
    }

    /* This loads from a file, a stack of x509/crl/pkey sets */
    if(!(sk = PEM_X509_INFO_read_bio(in,NULL,NULL,NULL))) {
        goto end;
    }

    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk))
        {
        xi = sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL)
            {
            sk_X509_push(stack,xi->x509);
            xi->x509 = NULL;
            }
        X509_INFO_free(xi);
        }
    if(!sk_X509_num(stack)) {
        sk_X509_free(stack);
        goto end;
    }
    ret = stack;
end:
    BIO_free(in);
    sk_X509_INFO_free(sk);
    return(ret);
    }

static int check(X509_STORE *ctx, const char *file, STACK_OF(X509) *uchain)
{
    X509 *x = NULL;
    int i = 0,ret = 0;
    X509_STORE_CTX *csc;

    x = load_cert(file);
    if (x == NULL)
        goto end;

    csc = X509_STORE_CTX_new();
    if (csc == NULL)
        goto end;
    X509_STORE_set_flags(ctx, 0);
    if(!X509_STORE_CTX_init(csc,ctx,x,uchain))
        goto end;
    i = X509_verify_cert(csc);
    X509_STORE_CTX_free(csc);

    ret = 0;
end:
    ret = (i > 0);
    if (x != NULL)
        X509_free(x);

    return(ret);
}