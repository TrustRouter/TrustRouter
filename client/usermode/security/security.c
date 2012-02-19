#include <Python.h>
#include <openssl/x509v3.h>

static PyObject *OpenSSL_Error;

// Helper

X509 *
create_x509_from_der(Py_buffer *der) {
    X509 *cert = d2i_X509(NULL, (const unsigned char **)&(der->buf), der->len);
    if (cert == NULL) {
        PyErr_SetString(OpenSSL_Error,
                        "not a valid DER-encoded X509 certificate");
    }
    return cert;
}

// CertificateStack

typedef struct {
    PyObject_HEAD
    STACK_OF(X509) *stack;
} CertificateStack;

static void
CertificateStack_dealloc(CertificateStack *self)
{
    if (self->stack != NULL) {
        sk_X509_pop_free(self->stack, X509_free);   
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static int
CertificateStack_init(CertificateStack *self)
{
    STACK_OF(X509) *stack = sk_X509_new_null();
    if (stack == NULL) {
        return -1;
    }

    if (self->stack != NULL) {
        sk_X509_pop_free(self->stack, X509_free);
    }
    self->stack = stack;
    return 0;
}

static PyObject *
CertificateStack_add(CertificateStack *self, PyObject *args)
{
    Py_buffer der_bytes;
    X509 *cert;

    if (!PyArg_ParseTuple(args, "y*", &der_bytes)) {
        return NULL;
    }

    cert = create_x509_from_der(&der_bytes);
    if (cert == NULL) return NULL;

    sk_X509_push(self->stack, cert);
    Py_RETURN_NONE;
}

static PyObject *
CertificateStack_verify_prefix(CertificateStack *self, PyObject *args)
{
    char *prefix_str;
    X509_EXTENSION *prefix_ext;
    IPAddrBlocks *prefix_blocks;
    int ret;

    if (!PyArg_ParseTuple(args, "s", &prefix_str)) {
        return NULL;
    }

    prefix_ext = X509V3_EXT_conf_nid(NULL, NULL,
                                     NID_sbgp_ipAddrBlock, prefix_str);
    if (prefix_ext == NULL) goto error;

    prefix_blocks = (IPAddrBlocks *)X509V3_EXT_d2i(prefix_ext);
    X509_EXTENSION_free(prefix_ext);
    if (prefix_blocks == NULL) goto error;

    ret = v3_addr_validate_resource_set(self->stack, prefix_blocks, 0);
    sk_IPAddressFamily_pop_free(prefix_blocks, IPAddressFamily_free);

    return PyBool_FromLong(ret);

error:
    PyErr_SetString(OpenSSL_Error,
                        "cannot create ipAddrExtension from prefix");
    return NULL;
}

static PyMethodDef CertificateStack_methods[] = {
    {"add", (PyCFunction)CertificateStack_add, METH_VARARGS,
     "adds a DER-encoded certificate to the stack"
    },
    {"verify_prefix", (PyCFunction)CertificateStack_verify_prefix, METH_VARARGS,
     "checks if prefix is within certified range (stack must be a certificate chain)"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject CertificateStackType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "security.CertificateStack", /* tp_name */
    sizeof(CertificateStack),  /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)CertificateStack_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "Stack of x509 certificates", /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    CertificateStack_methods,  /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)CertificateStack_init, /* tp_init */
};

// Certificate

typedef struct {
    PyObject_HEAD
    X509 *certificate;
} Certificate;

static void
Certificate_dealloc(Certificate *self)
{
    if (self->certificate != NULL) {
        X509_free(self->certificate);   
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
Certificate_init(Certificate *self, PyObject *args)
{
    Py_buffer der_bytes;
    X509 *cert;

    if (!PyArg_ParseTuple(args, "y*", &der_bytes)) {
        return -1;
    }

    cert = create_x509_from_der(&der_bytes);
    if (cert == NULL) return -1;

    if (self->certificate != NULL) {
        X509_free(self->certificate);
    }
    self->certificate = cert;

    return 0;
}

static PyObject *
Certificate_get_chain(Certificate *self, PyObject *args)
{
    CertificateStack *trusted;
    CertificateStack *intermediate;
    X509_STORE_CTX *ctx;
    STACK_OF(X509) *chain;
    CertificateStack *ret;
       
    if (!PyArg_ParseTuple(args, "O!O!",
                          &CertificateStackType, (PyObject *)&(trusted),
                          &CertificateStackType, (PyObject *)&(intermediate))) {
        return NULL;   
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) goto error;
    if (X509_STORE_CTX_init(ctx, NULL,
                            self->certificate,
                            intermediate->stack) != 1) goto error;
    X509_STORE_CTX_trusted_stack(ctx, trusted->stack);

    chain = NULL;
    if (X509_verify_cert(ctx) == 1) {
        chain = X509_STORE_CTX_get1_chain(ctx);
    }
#ifdef DEBUG
    else {
        printf("%s\n",
               X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }
#endif

    X509_STORE_CTX_free(ctx);

    if (chain == NULL) {
        Py_RETURN_NONE;
    }

    ret = PyObject_New(CertificateStack, &CertificateStackType);
    ret->stack = chain;
    return (PyObject *)ret;

error:
    if (ctx != NULL) X509_STORE_CTX_free(ctx);
    PyErr_SetString(OpenSSL_Error,
                    "cannot create X509_STORE_CTX");
    return NULL;
}

static PyObject *
Certificate_verify_signature(Certificate *self, PyObject *args)
{
    Py_buffer signed_data;
    Py_buffer signature;
    EVP_PKEY *pubkey_evp;
    RSA *pubkey;
    char hash[SHA_DIGEST_LENGTH];
    int ret;

    if (!PyArg_ParseTuple(args, "y*y*", &signed_data, &signature)) {
        return NULL;
    }

    pubkey_evp = X509_get_pubkey(self->certificate);
    if (pubkey_evp == NULL) goto error;
    pubkey = EVP_PKEY_get1_RSA(pubkey_evp);
    EVP_PKEY_free(pubkey_evp);
    if (pubkey == NULL) goto error;
    
    SHA1(signed_data.buf, signed_data.len, (unsigned char *)&hash);

    ret = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH,
                     signature.buf, RSA_size(pubkey), pubkey);

#ifdef DEBUG
    if (ret != 1) {
        char a[255];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), a);
        printf("%s\n", a);
        ERR_free_strings();
    }
#endif

    RSA_free(pubkey);

    return PyBool_FromLong(ret);

error:
    PyErr_SetString(OpenSSL_Error,
                    "cannot extract public RSA key from certificate");
    return NULL;
}

static PyMethodDef Certificate_methods[] = {
    {"get_chain", (PyCFunction)Certificate_get_chain, METH_VARARGS,
     "returns a chain of certificates to current certificate, if it existes. "
     "Chain starts with a trust anchor followed by intermediate certificates."
    },
    {"verify_signature", (PyCFunction)Certificate_verify_signature, METH_VARARGS,
     "verify signature with public key of certificate"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject CertificateType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "security.Certificate",    /* tp_name */
    sizeof(Certificate),       /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)Certificate_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "X509 certificate",        /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    Certificate_methods,       /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Certificate_init, /* tp_init */
};

// security module

void
free_security(void *x) {
    EVP_cleanup();
}

static PyModuleDef securitymodule = {
    PyModuleDef_HEAD_INIT,
    "security",
    "security Module for x509 certificate handling",
    -1,
    NULL, NULL, NULL, NULL, free_security
};

PyMODINIT_FUNC
PyInit_security(void)
{
    PyObject* m;

#ifdef DEBUG
    printf("Debug mode\n");
#endif

    m = PyModule_Create(&securitymodule);
    if (m == NULL) return NULL;

    CertificateStackType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&CertificateStackType) < 0) return NULL;
    Py_INCREF(&CertificateStackType);
    PyModule_AddObject(m, "CertificateStack", (PyObject *)&CertificateStackType);

    CertificateType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&CertificateType) < 0) return NULL;
    Py_INCREF(&CertificateType);
    PyModule_AddObject(m, "Certificate", (PyObject *)&CertificateType);

    OpenSSL_Error = PyErr_NewException("security.OpenSSL_Error", NULL, NULL);
    Py_INCREF(OpenSSL_Error);
    PyModule_AddObject(m, "OpenSSL_Error", OpenSSL_Error);

    OpenSSL_add_all_algorithms();

    return m;
}
