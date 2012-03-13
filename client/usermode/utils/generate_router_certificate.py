#!/usr/bin/python3

import math
import os
import os.path
import argparse 

# need to use arbitrary extension encoding, since enable-rfc3779 flag cannot be assumed
# OID 1.3.6.1.5.5.7.1.7 = sbgp-ipAddrBlock
OID = "1.3.6.1.5.5.7.1.7"

def _input_to_bool(string):
    return string.lower() in ["y", "yes", "ja", "j", "true", "t", "1"]

def generate_CA_certificate(ca_base_name):
    use_existing_ca = _input_to_bool(
        input(
            "\nUse an existing Certificate Authority? (Need private key and valid resource certificate with Address Extension from CA.) \t y/n? \t"
        )
    )

    if not use_existing_ca:
        der_path = ca_base_name + ".der"
        key_path = ca_base_name + ".key"
        csr_path = ca_base_name + ".csr"
        subject = input("\nName for CA? (Subject/Issuer for certificate) \t")
        valid_days = int(input("\nHow many days should the certificate be valid? \t"))
        key_length = int(input("\nBit-length of key? \t"))
        ext_path = generate_CA_extfile(ca_base_name)

        # return value from openssl-apps is always 0, cannot check properly, if command was successfull
        # assume success at the end, failure is indicated by openssl-prints
        generate_key_cmd = "openssl genrsa -out %s %d" % (key_path, key_length)
        print("\nrunning: '%s'\n" % generate_key_cmd)
        os.system(generate_key_cmd)

        generate_csr_cmd = "openssl req -new -key %s -out %s -subj '/CN=%s' -days %d" % (key_path, csr_path, subject, valid_days)
        print("\nrunning: '%s'\n" % generate_csr_cmd)
        os.system(generate_csr_cmd)

        generate_der_cmd = "openssl x509 -days %d -extfile %s -signkey %s -in %s -req -outform DER -out %s" % (valid_days, ext_path, key_path, csr_path, der_path)
        print("\nrunning: '%s'\n" % generate_der_cmd)
        os.system(generate_der_cmd)
        
        print("\nIf all openssl calls were successfull: The new DER-encoded CA certificate is %s, the private keyfile is %s." % (der_path, key_path))
        print("\nThe extension file %s and the certificate signing request %s used for the CA certificate generation can be deleted or reused." % (ext_path, csr_path))
    
    else:

        key_path = input("\nPath to CAs private key? \t")
        if not os.path.isfile(key_path):
            raise RuntimeError("%s does not point to a file." % key_path)

        der_path = input("\nPath to DER-encoded CA certificate? \t")
        if not os.path.isfile(der_path):
            raise RuntimeError("%s does not point to a file." % der_path)

    return { "key_path" : key_path, "der_path" : der_path }

def generate_router_certificate(ca_key_path, ca_der_path, router_base_name):
    der_path = router_base_name + ".der"
    key_path = router_base_name + ".key"
    csr_path = router_base_name + ".csr"

    subject = input("\nName for Router? (Subject for certificate) \t")
    valid_days = int(input("\nHow many days should the certificate be valid? \t"))
    key_length = int(input("\nBit-length of key? \t"))
    serial = input("\nSerial for certificate? (Should be unique among issued certificates from same CA, hex-number like 0x01) \t")
    serial = int(serial, 16)
    prefix_string = input("\nWhich prefix should the router advertise? (IPAddress Extension) Please enter in format 'significant_bytes\prefix_length'. Explicitly enter all significant bytes of IPv6-prefix, no short-notation (::), e.g. /0, 2001:0638:0807:021d/64. When in doubt, enter all_bytes/prefix_length. \n")
    prefix_split = prefix_string.split("/")
    prefix = prefix_split[0]
    prefix_length = int(prefix_split[1])

    if not (0 <= prefix_length < 128):
        raise RuntimeError("\nPrefix length must be greater or equal to 0 and smaller than 128. Given: %d\n", prefix_length)
    ext_path = generate_router_extfile(prefix, prefix_length, router_base_name)

    # return value from openssl-apps is always 0, cannot check properly, if command was successfull
    # assume success at the end, failure is indicated by openssl-prints
    generate_key_cmd = "openssl genrsa -out %s %d" % (key_path, key_length)
    print("\nrunning: '%s'\n" % generate_key_cmd)
    os.system(generate_key_cmd)

    generate_csr_cmd = "openssl req -new -key %s -out %s -subj '/CN=%s' -days %d" % (key_path, csr_path, subject, valid_days)
    print("\nrunning: '%s'\n" % generate_csr_cmd)
    os.system(generate_csr_cmd)
    
    generate_der_cmd = "openssl x509 -days %d -extfile %s -CAform DER -CA %s -CAkey %s -set_serial %d -sha256 -in %s -req -outform DER -out %s" % (valid_days, ext_path, ca_der_path, ca_key_path, serial, csr_path, der_path)
    print("\nrunning: '%s'\n" % generate_der_cmd)
    os.system(generate_der_cmd)

    print("\nIf all openssl calls were successfull: The new DER-encoded router certificate is %s, the private keyfile is %s." % (der_path, key_path))
    print("\nThe extension file %s and the certificate signing request %s for the router certificate generation can be deleted or reused." % (ext_path, csr_path))

    return { "key_path" : key_path, "der_path" : der_path }


def generate_router_extfile(prefix, prefix_length, router_base_name):
    ext_path = router_base_name + ".ext"

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

def generate_CA_extfile(ca_base_name):
    ext_path = ca_base_name + ".ext"
    fh = open(ext_path, "w")
    fh.write("extensions = x509v3\n")
    fh.write("[ x509v3 ]\n")
    fh.write("subjectKeyIdentifier    = hash\n")
    fh.write("basicConstraints    = critical, CA:true\n")
    fh.write("keyUsage            = critical, keyCertSign, cRLSign\n")

    # use ::/0 as prefix for CA
    prefix_der_string = _v6_prefix_to_der_string("", 0)
    fh.write("%s = critical, DER:%s\n" % (OID, prefix_der_string))
    fh.close()
    return ext_path

def _v6_prefix_to_der_string(prefix, prefix_length):
    address = []

    for double_byte in prefix.split(":"):
        if len(double_byte) % 2 != 0:
            raise RuntimeError("Found Half-byte: Bytes are represented by two hex-digits. Therefore number of chars in prefix must be multiple of two.")
        address.append(double_byte[0:2])
        if len(double_byte) > 4:
            raise RuntimeError("Found oversized Byte-block: IPv6-addresses are represented by blocks of two bytes (two hex-digits per byte) separated by a double-point ':'. Therefore number of chars between two ':' must be four.")
        if len(double_byte) == 4:
            address.append(double_byte[2:4])

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
    return der

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script for generating new router certificate, which can be used for SEcure Neighbour Discovery (SEND).')
    parser.add_argument('--ca_base_out', action="store", dest="CA_BASE_NAME", default="CA", type=str, help="base name for CA-related outputs")
    parser.add_argument('--router_base_out', action="store", dest="ROUTER_BASE_NAME", default="router", type=str, help="base name for router-related outputs")
    args = parser.parse_args()
    ca = generate_CA_certificate(args.CA_BASE_NAME)
    generate_router_certificate(ca["key_path"], ca["der_path"], args.ROUTER_BASE_NAME)