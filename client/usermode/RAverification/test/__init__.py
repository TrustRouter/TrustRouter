#!/usr/bin/python
# -*- coding: utf-8 -*-

# Note: the tests depend on the certificates, which makes them time-dependent, because the certificates will expire at some point

import sys
import os
module_path = os.path.abspath(__file__)
module_directory = os.path.split(module_path)[0]
upper_directory = os.path.split(module_directory)[0]

from RAverification import verify_signature, _verify_signature
from RAverification import verify_prefix_with_cert, _verify_prefix_with_cert
from RAverification import _format_to_bytes

o_data_directory = module_directory + "/example_data/" + "only_one_block/"
m_data_directory = module_directory + "/example_data/" + "multiple_blocks/"

ripe_o = o_data_directory + "ripe/ripe.cer"
dfn_o = o_data_directory + "dfn/dfn.cer"
uni_o = o_data_directory + "uni_potsdam/uni_potsdam.cer"
hpi_o = o_data_directory + "hpi/hpi.cer"
dfn_uni_hpi_o = o_data_directory + "dfn+uni_potsdam+hpi.cer"

router0_o = o_data_directory + "router0/router0.cer"
router1_o = o_data_directory + "router1_correct/router1.cer"
router2_o = o_data_directory + "router2_faulty_range/router2.cer"
router3_o = o_data_directory + "router3_faulty_selfsigned/router3.cer"

signed_ra_path = o_data_directory + "router0/signed_data"
ra_signature_path = o_data_directory + "router0/signature"

ripe_m = m_data_directory + "ripe/ripe.cer"
dfn_m = m_data_directory + "dfn/dfn.cer"
uni_m = m_data_directory + "uni_potsdam/uni_potsdam.cer"
hpi_m = m_data_directory + "hpi/hpi.cer"
dfn_uni_hpi_m = m_data_directory + "dfn+uni_potsdam+hpi.cer"
router0_m = m_data_directory + "router0/router0.cer"

fh = open(signed_ra_path, "rb")
signed_ra = fh.read()
fh.close()

fh = open(ra_signature_path, "rb")
ra_signature = fh.read()
fh.close()

prefix_b = bytearray(b'\x20\x01\x06\x38\x08\x07\x02\x1d\x00\x00\x00\x00\x00\x00\x00\x00')
prefix_bad = bytearray(b'\x20\x03\x06\x38\x08\x07\x02\x1d\x00\x00\x00\x00\x00\x00\x00\x00')
prefix_length = 64
prefix_ext_0 = "IPv6:2001:638:807:21d::/64"
prefix_ext_1 = "IPv6:2001:0638::/32"

def test_verify_prefix():
    assert _verify_prefix_with_cert(
                _format_to_bytes(ripe_o), 
                None, 
                _format_to_bytes(dfn_o), 
                _format_to_bytes(prefix_ext_0)
            ) == 1
    assert _verify_prefix_with_cert(
                _format_to_bytes(ripe_o),
                _format_to_bytes(dfn_uni_hpi_o), 
                _format_to_bytes(router1_o),
                _format_to_bytes(prefix_ext_0)
            ) == 1
    assert _verify_prefix_with_cert(
                _format_to_bytes(ripe_o), 
                _format_to_bytes(dfn_uni_hpi_o),
                _format_to_bytes(router1_o),
                _format_to_bytes(prefix_ext_1)
            ) == 0
    assert verify_prefix_with_cert(ripe_o, None, dfn_o, prefix_b, prefix_length) == True
    assert verify_prefix_with_cert(ripe_o, dfn_o, uni_o, prefix_b, prefix_length) == True
    assert verify_prefix_with_cert(ripe_o, None, uni_o, prefix_b, prefix_length) == False
    assert verify_prefix_with_cert(ripe_o, dfn_uni_hpi_o, router1_o, prefix_b, prefix_length) == True
    assert verify_prefix_with_cert(ripe_o, dfn_uni_hpi_o, router2_o, prefix_b, prefix_length) == False
    assert verify_prefix_with_cert(ripe_o, dfn_uni_hpi_o, router3_o, prefix_b, prefix_length) == False
    assert verify_prefix_with_cert(ripe_o, dfn_uni_hpi_o, router1_o, prefix_b, prefix_length - 1) == False
    assert verify_prefix_with_cert(ripe_o, None, dfn_o, prefix_bad, prefix_length) == False
    assert verify_prefix_with_cert(ripe_o, dfn_uni_hpi_o, router1_o, prefix_bad, prefix_length) == False
    assert verify_prefix_with_cert(ripe_m, None, dfn_m, prefix_b, prefix_length) == True
    assert verify_prefix_with_cert(ripe_m, dfn_m, uni_m, prefix_b, prefix_length) == True
    assert verify_prefix_with_cert(ripe_m, None, uni_m, prefix_b, prefix_length) == False
    assert verify_prefix_with_cert(ripe_m, dfn_uni_hpi_m, router0_m, prefix_b, prefix_length) == True
    assert verify_prefix_with_cert(ripe_m, dfn_uni_hpi_m, router0_m, prefix_b, prefix_length - 1) == False
    assert verify_prefix_with_cert(ripe_m, None, dfn_m, prefix_bad, prefix_length) == False

def test_verify_signature():
    assert verify_signature(router0_o, signed_ra, ra_signature) == True
    assert verify_signature(router1_o, signed_ra, ra_signature) == False
    assert verify_signature(router2_o, signed_ra, ra_signature) == False
    assert verify_signature(router3_o, signed_ra, ra_signature) == False


def run_tests():
    test_verify_signature()
    test_verify_prefix()
    print("Done.")