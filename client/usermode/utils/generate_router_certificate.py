#!/usr/bin/python3

import math
import os

# need to use arbitrary extension encoding, since enable-rfc3779 flag cannot be assumed
# OID 1.3.6.1.5.5.7.1.7 = sbgp-ipAddrBlock
OID = "1.3.6.1.5.5.7.1.7"

def _input_to_bool(string):
    return string.lower() in ["y", "yes", "ja", "j", "true", "t", "1"]

def generate_CA_certificate():
    use_existing_ca = _input_to_bool(
    input(
        "\nUse existing Certificate Authority? y/n (Need private key and valid resource certificate with Address Extension from CA.) \t")
)
    if not use_existing_ca:
        base_name = "CA"
        ca_path = base_name + ".der"
        ca_key = base_name + ".key"
        ca_csr = base_name + ".csr"
        subject = input("\nName for CA? (Subject/Issuer for certificate) \t")
        valid_days = int(input("\nHow many days should the certificate be valid? \t"))
        key_length = int(input("\nBit-length of key? \t"))
        ext_path = generate_CA_extfile()
        os.system(
            "openssl genrsa -out %s %d" % (ca_key, key_length)
        )
        os.system(
            "openssl req -new -key %s -out %s -subj '/CN=%s' -days %d" % (ca_key, ca_csr, subject, valid_days)
        )
        os.system(
            "openssl x509 -days %d -extfile %s -signkey %s -in %s -req -outform DER -out %s" % (valid_days, ext_path, ca_key, ca_csr, ca_path)
        )
        print("\nThe new DER-encoded CA certificate is %s, the private keyfile is %s." % (ca_path, ca_key))
        print("\nThe extension file %s and the certificate signing request %s for the CA certificate generation can be deleted or reused." % (ext_path, ca_csr))
    else:
        ca_key = input("\nPath to CAs private key? \t")
        ca_path = input("\nPath to DER-encoded CA certificate? \t")

    return { "key" : ca_key, "cert" : ca_path }

def generate_router_certificate(ca_key_path, ca_cert_path):
    base_name = "router"
    router_path = base_name + ".der"
    router_key = base_name + ".key"
    router_csr = base_name + ".csr"

    subject = input("\nName for Router? (Subject for certificate) \t")
    valid_days = int(input("\nHow many days should the certificate be valid? \t"))
    key_length = int(input("\nBit-length of key? \t"))
    serial = input("\nSerial for certificate? (Should be unique among issued certificates from same CA, hex-number like 0x01) \t")
    serial = int(serial, 16)
    prefix_string = input("\nWhich prefix should the router advertise? (IPAddress Extension) Give full IPv6-Address(no short-notation) and /prefix_length, e.g. 0000:0000:0000:0000:0000:0000:0000:0000/0 \n")
    prefix_split = prefix_string.split("/")
    prefix = prefix_split[0]
    prefix_length = int(prefix_split[1])

    if len(prefix) != 39:
        raise RuntimeError("\nPlease give full IPv6-Address, no short-notation. e.g. 0000:0000:0000:0000:0000:0000:0000:0000/0\n")
    if not (0 <= prefix_length <= 127):
        raise RuntimeError("\nPrefix must be greater or equal to 0 and smaller than 128. Given: %d\n", prefix_length)
    ext_path = generate_router_extfile(prefix, prefix_length)

    os.system(
        "openssl genrsa -out %s %d" % (router_key, key_length)
    )
    os.system(
        "openssl req -new -key %s -out %s -subj '/CN=%s' -days %d" % (router_key, router_csr, subject, valid_days)
    )
    os.system(
        "openssl x509 -days %d -extfile %s -CAform DER -CA %s -CAkey %s -set_serial %d -sha256 -in %s -req -outform DER -out %s" % (valid_days, ext_path, ca_cert_path, ca_key_path, serial, router_csr, router_path)
    )
    print("\nThe new DER-encoded router certificate is %s, the private keyfile is %s." % (router_path, router_key))
    print("\nThe extension file %s and the certificate signing request %s for the router certificate generation can be deleted or reused." % (ext_path, router_csr))


def generate_router_extfile(prefix, prefix_length):
    ext_path = "router.ext"
    fh = open(ext_path, "w")
    fh.write("extensions = x509v3\n")
    fh.write("[ x509v3 ]\n")
    fh.write("subjectKeyIdentifier    = hash\n")
    fh.write("authorityKeyIdentifier = keyid\n")
    fh.write("basicConstraints    = critical, CA:false\n")
    fh.write("keyUsage            = critical, digitalSignature\n")
    prefix_der_string = _v6_prefix_to_der_string(prefix, prefix_length)
    fh.write("%s = critical, DER:%s\n" % (OID, prefix_der_string))
    return ext_path

def generate_CA_extfile():
    ext_path = "CA.ext"
    fh = open(ext_path, "w")
    fh.write("extensions = x509v3\n")
    fh.write("[ x509v3 ]\n")
    fh.write("subjectKeyIdentifier    = hash\n")
    fh.write("basicConstraints    = critical, CA:true\n")
    fh.write("keyUsage            = critical, keyCertSign, cRLSign\n")
    prefix_der_string = _v6_prefix_to_der_string("0000:0000:0000:0000:0000:0000:0000:0000", 0)
    fh.write("%s = critical, DER:%s\n" % (OID, prefix_der_string))
    fh.close()
    return ext_path

def _v6_prefix_to_der_string(prefix, prefix_length):
    address = []
    for double_byte in prefix.split(":"):
        address.append(double_byte[:2])
        address.append(double_byte[2:])
    used_bytes = math.ceil(prefix_length / 8)
    unused_bits = used_bytes * 8 - prefix_length
    # SHORT FORM-encoding, because tags of types are less than 30
    # 03 : BITSTRING (universal, primitive, type 3) + LengthInBytes (used_bytes + 1 Bytes for unused_bits) + UnusedBits + SignificantAddressBytes
    address_der = "03%02x%02x" % (used_bytes + 1, unused_bits)
    address_der += used_bytes * "%02x" % tuple(map(lambda x: int(x, 16),address[:used_bytes]))
    # address is contained in a sequence of addressranges
    # 30 : SEQUENCE (universal, constructed, type 16) + LengthInBytes
    address_der = "30%02x" % (len(address_der) / 2) + address_der
    # 04 : OCTETSTRING (universal, primitive, type 4) + 2 Byte Length, 00 02 for IPV6
    address_family = "04020002"
    # address family is contained in sequence, that encapsulates addressranges
    # 30 : SEQUENCE + LengthInBytes(address_family + addres_der)
    address_family = "30%02x" % ((len(address_family) + len(address_der)) / 2) + address_family
    address_family += address_der
    # addressblocks are a sequence of address families
    # 30 : SEQUENCE + LengthInBytes
    der = "30%02x" % (len(address_family) / 2)
    der += address_family
    return der.upper()

if __name__ == "__main__":
    ca = generate_CA_certificate()
    generate_router_certificate(ca["key"], ca["cert"])