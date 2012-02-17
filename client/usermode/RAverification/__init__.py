#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import platform
from ctypes import CDLL, c_char_p, c_int
import base64
import tempfile

module_path = os.path.abspath(__file__)
module_directory = os.path.split(module_path)[0]
lib_directory = module_directory + "/lib/"

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

_verify_prefix_with_cert = libsecurity.verify_prefix_with_cert
_verify_prefix_with_cert.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
_verify_prefix_with_cert.restype = c_int

def _der_to_pem(cert_der):
    cert_pem = "-----BEGIN CERTIFICATE-----\n".encode("ascii")
    cert_pem += base64.encodebytes(cert_der)
    cert_pem += "-----END CERTIFICATE-----\n".encode("ascii")
    return cert_pem

def _format_to_bytes(string):
    if string == None:
        return string
    else:
        assert isinstance(string, str)
        return bytes(string.encode(sys.stdin.encoding))

def _ipv4_n_to_a(address):
    return "%u.%u.%u.%u" % tuple(address)

def _ipv6_n_to_a(address):
    return "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % tuple(address)

def _get_ipaddrblock_ext(prefix, prefix_length):
    assert (len(prefix) == 16) or (len(prefix) == 4) 
    if len(prefix) == 16:
        ext = "IPv6:"
        ext += _ipv6_n_to_a(prefix)

    if len(prefix) == 4:
        ext = "IPv4:"
        ext += _ipv4_n_to_a(prefix)

    ext += "/"
    ext += str(prefix_length)
    return ext

def _create_temp_untrusted(untrusted_certs):
    if len(untrusted_certs) == 0:
        return None
    untrusted_file_tuple = tempfile.mkstemp()
    untrusted_file_handle = untrusted_file_tuple[0]
    untrusted_path = untrusted_file_tuple[1]
    untrusted_file = os.fdopen(untrusted_file_handle, "wb")
    for cert_der in untrusted_certs:
        untrusted_file.write(_der_to_pem(cert_der))
    untrusted_file.close()
    return untrusted_path

def _create_temp_cert(cert_der):
    cert_file_tuple = tempfile.mkstemp()
    cert_file_handle = cert_file_tuple[0]
    cert_path = cert_file_tuple[1]
    cert_file = os.fdopen(cert_file_handle, "wb")
    cert_file.write(_der_to_pem(cert_der))
    cert_file.close()
    return cert_path

# OpenSSL Return-Value  : bool
#               0       : False
#               1       : True
#           -1 (error)  : False --> better a false negative than a false positive

# str(path_to_PEM_file), list<bytes(DER-encoded cert)>, bytes(DER-encoded cert)  
def verify_cert(CAcert_path, untrusted_certs, cert):
    tmp_untrusted_path = _create_temp_untrusted(untrusted_certs)
    tmp_cert_path = _create_temp_cert(cert)
    valid = -1
    try:
        valid = _verify_cert(
            _format_to_bytes(CAcert_path),
            _format_to_bytes(tmp_untrusted_path),      
            _format_to_bytes(tmp_cert_path)  
        )
    finally:
        if tmp_untrusted_path != None:
            os.remove(tmp_untrusted_path)
        os.remove(tmp_cert_path)
    return 0 < valid

# CA and untrusted are needed, because the resources in cert could be inherited
# str(path_to_PEM_file), list<bytes(DER-encoded cert)>, bytes(DER-encoded cert), bytearray(prefix), int(prefix_length)
def verify_prefix_with_cert(CAcert_path, untrusted_certs, cert, prefix, prefix_length):
    prefix_ext = _get_ipaddrblock_ext(bytes(prefix), prefix_length)
    tmp_untrusted_path = _create_temp_untrusted(untrusted_certs)
    tmp_cert_path = _create_temp_cert(cert)
    valid = -1
    try:
        valid = _verify_prefix_with_cert(
            _format_to_bytes(CAcert_path),
            _format_to_bytes(tmp_untrusted_path),
            _format_to_bytes(tmp_cert_path),
            _format_to_bytes(prefix_ext)
        )
    finally:
        if tmp_untrusted_path != None:
            os.remove(tmp_untrusted_path)
        os.remove(tmp_cert_path)
    return 0 < valid

def verify_signature(signing_cert, signed_data, signature):
    # signing_cert      :   DER-encoded certificate which contains the public key,
    #                       corresponding to the private key, which was used to sign
    # signed_data       :   raw package data (bytes) which were signed to create 
    #                       the signature
    # signature         :   supposedly rsa_pkcs1_1.5 signature over sha1(signed_data)
    tmp_cert_path = _create_temp_cert(signing_cert)
    signing_cert_path = _format_to_bytes(tmp_cert_path)
    signature = bytes(signature)
    signed_data = bytes(signed_data) 
    signed = -1
    try:
        signed = _verify_signature(
            signing_cert_path, 
            signature, 
            signed_data, 
            len(signed_data)
        )
    finally:
        os.remove(tmp_cert_path)
    return 0 < signed


__all__ = [
    'test'
]