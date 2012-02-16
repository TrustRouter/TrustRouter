# -*- coding: utf-8 -*-

# Note: the tests depend on the certificates, which makes them time-dependent, because the certificates will expire at some point

import sys
import os
module_path = os.path.abspath(__file__)
module_directory = os.path.split(module_path)[0]
upper_directory = os.path.split(module_directory)[0]

from RAverification import verify_signature, _verify_signature
from RAverification import verify_prefix_with_cert, _verify_prefix_with_cert
from RAverification import verify_cert, _verify_cert
from RAverification import _format_to_bytes

o_data_directory = module_directory + "/example_data/" + "only_one_block/"
m_data_directory = module_directory + "/example_data/" + "multiple_blocks/"

ripe_o_pem_path = o_data_directory + "ripe/ripe.cer"
dfn_o_pem_path = o_data_directory + "dfn/dfn.cer"
uni_o_pem_path = o_data_directory + "uni_potsdam/uni_potsdam.cer"
hpi_o_pem_path = o_data_directory + "hpi/hpi.cer"
dfn_uni_hpi_o_path = o_data_directory + "dfn+uni_potsdam+hpi.cer"
router0_o_pem_path = o_data_directory + "router0/router0.cer"
router1_o_pem_path = o_data_directory + "router1_correct/router1.cer"
router2_o_pem_path = o_data_directory + "router2_faulty_range/router2.cer"
router3_o_pem_path = o_data_directory + "router3_faulty_selfsigned/router3.cer"

ripe_o_der_path = o_data_directory + "ripe/ripe.der"
dfn_o_der_path = o_data_directory + "dfn/dfn.der"
uni_o_der_path = o_data_directory + "uni_potsdam/uni_potsdam.der"
hpi_o_der_path = o_data_directory + "hpi/hpi.der"
router0_o_der_path = o_data_directory + "router0/router0.der"
router1_o_der_path = o_data_directory + "router1_correct/router1.der"
router2_o_der_path = o_data_directory + "router2_faulty_range/router2.der"
router3_o_der_path = o_data_directory + "router3_faulty_selfsigned/router3.der"

ripe_m_pem_path = m_data_directory + "ripe/ripe.cer"
dfn_m_pem_path = m_data_directory + "dfn/dfn.cer"
uni_m_pem_path = m_data_directory + "uni_potsdam/uni_potsdam.cer"
hpi_m_pem_path = m_data_directory + "hpi/hpi.cer"
dfn_uni_hpi_m_path = m_data_directory + "dfn+uni_potsdam+hpi.cer"
router0_m_pem_path = m_data_directory + "router0/router0.cer"

ripe_m_der_path = m_data_directory + "ripe/ripe.der"
dfn_m_der_path = m_data_directory + "dfn/dfn.der"
uni_m_der_path = m_data_directory + "uni_potsdam/uni_potsdam.der"
hpi_m_der_path = m_data_directory + "hpi/hpi.der"
router0_m_der_path = m_data_directory + "router0/router0.der"

signed_ra_path = o_data_directory + "router0/signed_data"
ra_signature_path = o_data_directory + "router0/signature"

fh = open(signed_ra_path, "rb")
signed_ra = fh.read()
fh.close()
fh = open(ra_signature_path, "rb")
ra_signature = fh.read()
fh.close()

fh = open(dfn_o_der_path, "rb")
dfn_o_der = fh.read()
fh.close()
fh = open(uni_o_der_path, "rb")
uni_o_der = fh.read()
fh.close()
fh = open(hpi_o_der_path, "rb")
hpi_o_der = fh.read()
fh.close()
fh = open(router0_o_der_path, "rb")
router0_o_der = fh.read()
fh.close()
fh = open(router1_o_der_path, "rb")
router1_o_der = fh.read()
fh.close()
fh = open(router2_o_der_path, "rb")
router2_o_der = fh.read()
fh.close()
fh = open(router3_o_der_path, "rb")
router3_o_der = fh.read()
fh.close()
fh = open(dfn_m_der_path, "rb")
dfn_m_der = fh.read()
fh.close()
fh = open(uni_m_der_path, "rb")
uni_m_der = fh.read()
fh.close()
fh = open(hpi_m_der_path, "rb")
hpi_m_der = fh.read()
fh.close()
fh = open(router0_m_der_path, "rb")
router0_m_der = fh.read()
fh.close()

prefix_b = bytearray(b'\x20\x01\x06\x38\x08\x07\x02\x1d\x00\x00\x00\x00\x00\x00\x00\x00')
prefix_bad = bytearray(b'\x20\x03\x06\x38\x08\x07\x02\x1d\x00\x00\x00\x00\x00\x00\x00\x00')
prefix_length = 64
prefix_ext_0 = "IPv6:2001:638:807:21d::/64"
prefix_ext_1 = "IPv6:2001:0638::/32"

def test_verify_prefix():
    assert _verify_prefix_with_cert(
                _format_to_bytes(ripe_o_pem_path), 
                None, 
                _format_to_bytes(dfn_o_pem_path), 
                _format_to_bytes(prefix_ext_0)
            ) == 1
    assert _verify_prefix_with_cert(
                _format_to_bytes(ripe_o_pem_path),
                _format_to_bytes(dfn_uni_hpi_o_path), 
                _format_to_bytes(router1_o_pem_path),
                _format_to_bytes(prefix_ext_0)
            ) == 1
    assert _verify_prefix_with_cert(
                _format_to_bytes(ripe_o_pem_path), 
                _format_to_bytes(dfn_uni_hpi_o_path),
                _format_to_bytes(router1_o_pem_path),
                _format_to_bytes(prefix_ext_1)
            ) == 0
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [],
        dfn_o_der,
        prefix_b,
        prefix_length
    ) == True
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [dfn_o_der],
        uni_o_der,
        prefix_b,
        prefix_length
    ) == True
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [],
        uni_o_der,
        prefix_b,
        prefix_length
    ) == False
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [dfn_o_der, uni_o_der, hpi_o_der],
        router1_o_der,
        prefix_b,
        prefix_length
    ) == True
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [dfn_o_der, uni_o_der, hpi_o_der],
        router2_o_der,
        prefix_b,
        prefix_length
    ) == False
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [dfn_o_der, uni_o_der, hpi_o_der],
        router3_o_der,
        prefix_b,
        prefix_length
    ) == False
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [dfn_o_der, uni_o_der, hpi_o_der],
        router1_o_der,
        prefix_b,
        prefix_length - 1
    ) == False
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [],
        dfn_o_der,
        prefix_bad,
        prefix_length
    ) == False
    assert verify_prefix_with_cert(
        ripe_o_pem_path,
        [dfn_o_der, uni_o_der, hpi_o_der],
        router1_o_der,
        prefix_bad,
        prefix_length
    ) == False
    assert verify_prefix_with_cert(
        ripe_m_pem_path,
        [],
        dfn_m_der,
        prefix_b,
        prefix_length
    ) == True
    assert verify_prefix_with_cert(
        ripe_m_pem_path,
        [dfn_m_der],
        uni_m_der,
        prefix_b,
        prefix_length
    ) == True
    assert verify_prefix_with_cert(
        ripe_m_pem_path,
        [],
        uni_m_der,
        prefix_b,
        prefix_length
    ) == False
    assert verify_prefix_with_cert(
        ripe_m_pem_path,
        [dfn_m_der, uni_m_der, hpi_m_der],
        router0_m_der,
        prefix_b,
        prefix_length
    ) == True
    assert verify_prefix_with_cert(
        ripe_m_pem_path,
        [dfn_m_der, uni_m_der, hpi_m_der],
        router0_m_der,
        prefix_b,
        prefix_length - 1
    ) == False
    assert verify_prefix_with_cert(
        ripe_m_pem_path,
        [],
        dfn_m_der,
        prefix_bad,
        prefix_length
    ) == False

def test_verify_signature():
    assert verify_signature(router0_o_der, signed_ra, ra_signature) == True
    assert verify_signature(router1_o_der, signed_ra, ra_signature) == False
    assert verify_signature(router2_o_der, signed_ra, ra_signature) == False
    assert verify_signature(router3_o_der, signed_ra, ra_signature) == False

def test_verify_cert():
    assert verify_cert(ripe_o_pem_path, [], dfn_o_der) == True
    assert verify_cert(ripe_o_pem_path, [dfn_o_der], uni_o_der) == True
    assert verify_cert(ripe_o_pem_path, [], uni_o_der) == False
    assert verify_cert(ripe_o_pem_path, [dfn_o_der, uni_o_der, hpi_o_der], router1_o_der) == True
    assert verify_cert(ripe_o_pem_path, [dfn_o_der, uni_o_der, hpi_o_der], router2_o_der) == False
    assert verify_cert(ripe_o_pem_path, [dfn_o_der, uni_o_der, hpi_o_der], router3_o_der) == False
    assert verify_cert(ripe_m_pem_path, [dfn_m_der, uni_m_der, hpi_m_der], router0_m_der) == True

def run_tests():
    test_verify_cert()
    test_verify_signature()
    test_verify_prefix()
    print("Done.")