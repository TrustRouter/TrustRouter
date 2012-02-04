#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import platform
from ctypes import CDLL, c_char_p, c_int

module_path = os.path.abspath(__file__)
module_directory = os.path.split(module_path)[0]
lib_directory = module_directory + "/security/lib/"

# platform-switch only for repository/developing
system = platform.system()

if system == "Windows":
    lib_directory += "Windows/"
    lib_name = "libsecurity.dll"
elif system == "Darwin":
    lib_directory += "MacOS/"
    lib_name = "libsecurity.dylib"
elif system == "Linux":
    lib_directory += "Linux/"
    lib_name = "libsecurity.so"
else:
    raise Exception("Unable to load security library. System: %s\n", system)

architecture = platform.architecture()[0]

if architecture == "64bit":
    lib_directory += "x64/"
elif architecture == "32bit":
    lib_directory += "ia32/"
else:
    raise Exception("Unable to load security library. Architecture: %s\n", architecture)

if not os.path.isfile(lib_directory + lib_name):
    raise Exception("Unable to load security library. Path: %s\n", lib_directory + lib_name)

libsecurity = CDLL(lib_directory + lib_name)

_verify_cert = libsecurity.verify_cert
_verify_cert.argtypes = [c_char_p, c_char_p, c_char_p]
_verify_cert.restype = c_int

_verify_signature = libsecurity.verify_signature
_verify_signature.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
_verify_signature.restype = c_int

_verify_prefix = libsecurity.verify_prefix
_verify_prefix.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
_verify_prefix.restype = c_int

def _format_to_bytes(string):
    if string == None:
        return string
    else:
        assert isinstance(string, str)
        return bytes(string.encode(sys.stdin.encoding))

# OpenSSL Code : bool
#       0       : False
#       1       : True
# -1 (error)    : False --> better a false negative than a false positive

#verify_prefix(signing_cert_path, prefix<bytearray>, prefixlength)
#CA and untrusted are needed, because the resources in cert could be inherited
def verify_prefix(signing_cert_path, prefix, prefix_length):
    #TODO
    return True

def verify_signature(signing_cert_path, signed_data, signature):
    # signing_cert_path :   path to the certificate which contains the public key,
    #                       corresponding to the private key, which was used to sign
    # signed_data       :   raw package data (bytes) which were signed to create 
    #                       the signature
    # signature         :   supposedly rsa_pkcs1_1.5 signature over sha1(signed_data)
    signing_cert_path = _format_to_bytes(signing_cert_path)
    signature = bytes(signature)
    signed_data = bytes(signed_data) 

    signed = _verify_signature(
        signing_cert_path, 
        signature, 
        signed_data, 
        len(signed_data)
    )
    return 0 < signed

# str(path_to_file), str(path_to_file) or None, str(path_to_file)
def verify_cert(CAcert_path, untrusted_certs_path, cert_path):
    valid = _verify_cert(
        _format_to_bytes(CAcert_path),
        _format_to_bytes(untrusted_certs_path), 
        _format_to_bytes(cert_path) 
    )
    return 0 < valid
