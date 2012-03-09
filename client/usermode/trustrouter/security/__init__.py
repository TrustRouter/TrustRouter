#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import os.path
import sys
import platform
from ctypes import CDLL, c_char_p, c_int

module_path = os.path.abspath(__file__)
module_directory = os.path.split(module_path)[0]
lib_directory = os.path.join(module_directory, "lib")

# platform-switch only for repository/developing
system = platform.system()

if system == "Windows":
    lib_directory = os.path.join(lib_directory, "Windows")
    lib_name = "libsecurity.dll"
elif system == "Darwin":
    lib_directory = os.path.join(lib_directory, "MacOS")
    lib_name = "libsecurity.dylib"
elif system == "Linux":
    lib_directory = os.path.join(lib_directory, "Linux")
    lib_name = "libsecurity.so"
else:
    raise Exception("Unable to load security library. System: %s\n" % system)

architecture = platform.architecture()[0]

if architecture == "64bit":
    lib_directory = os.path.join(lib_directory, "x64")
elif architecture == "32bit":
    lib_directory = os.path.join(lib_directory, "ia32")
else:
    raise Exception("Unable to load security library. Architecture: %s\n" % architecture)

lib_abspath = os.path.join(lib_directory, lib_name)
if not os.path.isfile(lib_abspath):
    raise Exception("Unable to load security library. Path: %s\n" % lib_abspath)

libsecurity = CDLL(lib_abspath)

_verify_cert = libsecurity.verify_cert
_verify_cert.argtypes = [c_int, c_int, c_char_p, c_int, c_int, c_char_p, c_int, c_char_p]
_verify_cert.restype = c_int

_verify_signature = libsecurity.verify_signature
_verify_signature.argtypes = [c_int, c_char_p, c_char_p, c_int, c_char_p]
_verify_signature.restype = c_int

_verify_prefix_with_cert = libsecurity.verify_prefix_with_cert
_verify_prefix_with_cert.argtypes = [c_int, c_int, c_char_p, c_int, c_int, c_char_p, c_int, c_char_p, c_char_p]
_verify_prefix_with_cert.restype = c_int

def _format_to_bytes(string):
    if string == None:
        return string
    else:
        assert isinstance(string, str)
        return bytes(string.encode("ascii"))

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

def _format_certs_der(certs_der):
    cert_count = len(certs_der)
    cert_length = 0
    certs_param = None

    if cert_count != 0:
        cert_length = len(max(certs_der, key=len))
        certs_param = b''
        for cert in certs_der:
            certs_param += cert
            certs_param += (cert_length - len(cert)) * b'\x00'
    return {"cert_count": cert_count, "cert_length": cert_length, "certs": certs_param}

# OpenSSL Return-Value  : bool
#               0       : False
#               1       : True
#           -1 (error)  : False --> better a false negative than a false positive

# list<bytes(DER-encoded cert)>, list<bytes(DER-encoded cert)>, bytes(DER-encoded cert)  
def verify_cert(CA_certs, untrusted_certs, cert):
    CAs = _format_certs_der(CA_certs)
    untrusted = _format_certs_der(untrusted_certs)
    valid = -1
    valid = _verify_cert(
        CAs["cert_count"],
        CAs["cert_length"],
        CAs["certs"],
        untrusted["cert_count"],
        untrusted["cert_length"],
        untrusted["certs"],    
        len(cert),
        cert
    )
    return 0 < valid

# CA and untrusted are needed, because the resources in cert could be inherited
# list<bytes(DER-encoded cert)>, list<bytes(DER-encoded cert)>, bytes(DER-encoded cert), bytearray(prefix), int(prefix_length)
def verify_prefix_with_cert(CA_certs, untrusted_certs, cert, prefix, prefix_length):
    prefix_ext = _get_ipaddrblock_ext(bytes(prefix), prefix_length)
    CAs = _format_certs_der(CA_certs)
    untrusted = _format_certs_der(untrusted_certs)
    valid = -1
    valid = _verify_prefix_with_cert(
        CAs["cert_count"],
        CAs["cert_length"],
        CAs["certs"],
        untrusted["cert_count"],
        untrusted["cert_length"],
        untrusted["certs"],
        len(cert),
        cert,
        _format_to_bytes(prefix_ext)
    )

    return 0 < valid

def verify_signature(signing_cert, signed_data, signature):
    # signing_cert      :   DER-encoded certificate which contains the public key,
    #                       corresponding to the private key, which was used to sign
    # signed_data       :   raw package data (bytes) which were signed to create 
    #                       the signature
    # signature         :   supposedly rsa_pkcs1_1.5 signature over sha1(signed_data)
    signature = bytes(signature)
    signed_data = bytes(signed_data) 
    signed = -1
    signed = _verify_signature(
        len(signing_cert), 
        signing_cert,
        signature,
        len(signed_data), 
        signed_data
    )

    return 0 < signed


__all__ = [
    'test'
]