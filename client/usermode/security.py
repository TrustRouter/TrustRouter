#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import platform
import tempfile
from ctypes import CDLL, c_char_p, c_int

module_path = os.path.abspath(__file__)
module_directory = os.path.split(module_path)[0]
lib_directory = module_directory + "/security/lib/"

if platform.system() == "Windows" and os.path.isfile(lib_directory + "libsecurity.1.1.dll"):
    libsecurity = CDLL(lib_directory + "libsecurity.1.1.dll")
elif platform.system() == "Darwin" and os.path.isfile(lib_directory + "libsecurity.1.1.dylib"):
    libsecurity = CDLL(lib_directory + "libsecurity.1.1.dylib")
elif platform.system() == "Linux" and os.path.isfile(lib_directory + "libsecurity.1.1.so"):
    libsecurity = CDLL(lib_directory + "libsecurity.1.1.so")
else:
    raise Exception("Unable to load security library.")

_verify_from_path = libsecurity.verify_cert_from_path
_verify_from_path.argtypes = [c_char_p, c_char_p, c_char_p]
_verify_from_path.restype = c_int

_signed_from_path = libsecurity.rsa_signed_with_cert
_signed_from_path.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
_signed_from_path.restype = c_int

def _format_to_bytes(string):
    if string == None:
        return string
    else:
        return bytes(string.encode(sys.stdin.encoding))

def has_signed(cert, signed_data, data):
    cert_file_tuple = tempfile.mkstemp()
    cert_file_handle = cert_file_tuple[0]
    cert_path = cert_file_tuple[1]
    cert_file = os.fdopen(cert_file_handle, "w")
    cert_file.write(cert)
    cert_file.close()
    was_signed = False
    try:
        was_signed = has_signed_from_path(cert_path, signed_data, data)
    finally:
        os.remove(cert_path)
    return was_signed

def has_signed_from_path(signing_cert_path, signed_data, data):
    signed = _signed_with_cert_from_path(signing_cert_path, signed_data, data)
    return 0 < signed

def _signed_with_cert_from_path(signing_cert_path, signed_data, data):
    signed_data_file_tuple = tempfile.mkstemp()
    signed_data_file_handle = signed_data_file_tuple[0]
    signed_data_path = signed_data_file_tuple[1]
    signed_data_file = os.fdopen(signed_data_file_handle, "wb")
    signed_data_file.write(signed_data)
    signed_data_file.close()
    signed = -1
    try:
        signed  = _signed_from_path_with_cert_from_path(signing_cert_path, signed_data_path, data)
    finally:
        os.remove(signed_data_path)
    return signed

def _signed_from_path_with_cert_from_path(signing_cert_path, signed_data_path, data):
    return _signed_from_path(_format_to_bytes(signing_cert_path), _format_to_bytes(signed_data_path), data, len(data))

# convenience methods which should return True only if path is valid
# OpenSSL Code : bool
#       0       : False
#       1       : True
# -1 (error)    : False --> better a false negative than a false positive

# str(path_to_file), str(path_to_file) or None, str(path_to_file)
def is_valid_chain_from_path(CAcert_path, untrusted_certs_path, cert_path):
    return 0 < _verify_cert_from_path(CAcert_path, untrusted_certs_path, cert_path)

#str, list<str>, str
def is_valid_chain(CAcert, untrusted_certs, cert):
    return 0 < _verify_cert(CAcert, untrusted_certs, cert)

# str(path_to_file), str(path_to_file) or None, str(path_to_file)
def _verify_cert_from_path(CAcert_path, untrusted_certs_path, cert_path):
    assert isinstance(CAcert_path, str)
    assert isinstance(cert_path, str)
    assert isinstance(untrusted_certs_path, str) or untrusted_certs_path == None
    return _verify_from_path(_format_to_bytes(CAcert_path), _format_to_bytes(cert_path), _format_to_bytes(untrusted_certs_path))

#str, list<str>, str
def _verify_cert(CAcert, untrusted_certs, cert):
    ca_file_tuple = tempfile.mkstemp()
    ca_file_handle = ca_file_tuple[0]
    CAcert_path = ca_file_tuple[1]
    ca_file = os.fdopen(ca_file_handle, "w")
    ca_file.write(CAcert)
    ca_file.close()

    cert_file_tuple = tempfile.mkstemp()
    cert_file_handle = cert_file_tuple[0]
    cert_path = cert_file_tuple[1]
    cert_file = os.fdopen(cert_file_handle, "w")
    cert_file.write(cert)
    cert_file.close()
    
    if not len(untrusted_certs) > 0:
        untrusted_certs_path = None
    else:
        untrusted_file_tuple = tempfile.mkstemp()
        untrusted_file_handle = untrusted_file_tuple[0]
        untrusted_certs_path = untrusted_file_tuple[1]
        untrusted_file = os.fdopen(untrusted_file_handle, "w")
        for crt in untrusted_certs:
            untrusted_file.write(crt)
        untrusted_file.close()
    assert isinstance(CAcert_path, str)
    assert isinstance(cert_path, str)
    assert isinstance(untrusted_certs_path, str) or untrusted_certs_path == None
    verification_status = -1
    try:
        verification_status = _verify_cert_from_path(CAcert_path, untrusted_certs_path, cert_path)
    finally:
        os.remove(CAcert_path)
        os.remove(cert_path)
        if untrusted_certs_path:
            os.remove(untrusted_certs_path)

    return verification_status