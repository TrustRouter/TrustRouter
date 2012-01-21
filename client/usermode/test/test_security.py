#!/usr/bin/python
# -*- coding: utf-8 -*-

# Note: the tests depend on the certificates, which makes them time-dependent, because the certificates will expire at some point

# we need to temporarily add the path containing the security-module to the python search-path for importing it - works but seems ugly
import sys
import os
module_path = os.path.abspath(__file__)
module_directory = os.path.split(module_path)[0]
upper_directory = os.path.split(module_directory)[0]
sys.path.insert(0, upper_directory)

from security import verify_cert, _verify_cert
from security import verify_signature, _verify_signature

data_directory = module_directory + "/example_data/"

ripe_o = data_directory + "ripe/ripe.cer"
dfn_o = data_directory + "dfn/dfn.cer"
uni_o = data_directory + "uni_potsdam/uni_potsdam.cer"
hpi_o = data_directory + "hpi/hpi.cer"
dfn_uni_hpi_o = data_directory + "dfn+uni_potsdam+hpi.cer"

router1 = data_directory + "router1_correct/router1.cer"
router2 = data_directory + "router2_faulty_range/router2.cer"
router3 = data_directory + "router3_faulty_selfsigned/router3.cer"

signed_data_path = data_directory + "router1_correct/testdata_raw"
signature_path = data_directory + "router1_correct/testdata_signed"
hashed_data_path = data_directory + "router1_correct/testdata_hashed"

fh = open(signed_data_path, "rb")
signed_data = fh.read()
fh.close()

fh = open(signature_path, "rb")
signature = fh.read()
fh.close()

fh = open(hashed_data_path, "rb")
hashed_data = fh.read()
fh.close()

fh = open(ripe_o, "r")
ripe_o_data = fh.read()
fh.close()

fh = open(dfn_o, "r")
dfn_o_data = fh.read()
fh.close()

fh = open(uni_o, "r")
uni_o_data = fh.read()
fh.close()

fh = open(hpi_o, "r")
hpi_o_data = fh.read()
fh.close()

fh = open(dfn_uni_hpi_o, "r")
dfn_uni_hpi_o_data = fh.read()
fh.close()

fh = open(router1, "r")
router1_data = fh.read()
fh.close()

fh = open(router2, "r")
router2_data = fh.read()
fh.close()

fh = open(router3, "r")
router3_data = fh.read()
fh.close()

def test_verify_cert():
    assert verify_cert(ripe_o, None, dfn_o) == True
    assert verify_cert(ripe_o, dfn_o, uni_o) == True
    assert verify_cert(ripe_o, None, uni_o) == False
    assert verify_cert(ripe_o, dfn_uni_hpi_o, router1) == True
    assert verify_cert(ripe_o, dfn_uni_hpi_o, router2) == False
    assert verify_cert(ripe_o, dfn_uni_hpi_o, router3) == False

def test_verify_signature():
    assert verify_signature(router1, signed_data, signature) == True
    assert verify_signature(router2, signed_data, signature) == False
    assert verify_signature(router3, signed_data, signature) == False


def run_tests():
    test_verify_cert()
    test_verify_signature()

