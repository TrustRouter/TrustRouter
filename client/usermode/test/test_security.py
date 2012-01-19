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

from security import is_valid_chain, is_valid_chain_from_path
from security import has_signed, has_signed_from_path
from security import _verify_cert_from_path, _verify_cert
from security import _signed_from_path_with_cert_from_path, _signed_with_cert_from_path

data_directory = module_directory + "/example_data/"

ripe_o = data_directory + "ripe/ripe.cer"
dfn_o = data_directory + "dfn/dfn.cer"
uni_o = data_directory + "uni_potsdam/uni_potsdam.cer"
hpi_o = data_directory + "hpi/hpi.cer"
dfn_uni_hpi_o = data_directory + "dfn+uni_potsdam+hpi.cer"

router1 = data_directory + "router1_correct/router1.cer"
router2 = data_directory + "router2_faulty_range/router2.cer"
router3 = data_directory + "router3_faulty_selfsigned/router3.cer"

data_path = data_directory + "router1_correct/testdata_raw"
signed_data_path = data_directory + "router1_correct/testdata_signed"

fh = open(data_path, "rb")
data = fh.read()
fh.close()

fh = open(signed_data_path, "rb")
signed_data = fh.read()
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

def test_verify_cert_from_path():
    assert _verify_cert_from_path(ripe_o, None, dfn_o) == 1
    assert _verify_cert_from_path(ripe_o, dfn_o, uni_o) == 1
    assert _verify_cert_from_path(ripe_o, None, uni_o) == 0
    assert _verify_cert_from_path(ripe_o, dfn_uni_hpi_o, router1) == 1
    assert _verify_cert_from_path(ripe_o, dfn_uni_hpi_o, router2) == 0
    assert _verify_cert_from_path(ripe_o, dfn_uni_hpi_o, router3) == 0

def test_verify_cert():
    assert _verify_cert(ripe_o_data, [], dfn_o_data) == 1
    assert _verify_cert(ripe_o_data, [dfn_o_data], uni_o_data) == 1
    assert _verify_cert(ripe_o_data, [], uni_o_data) == 0
    assert _verify_cert(ripe_o_data, [dfn_uni_hpi_o_data], router1_data) == 1
    assert _verify_cert(ripe_o_data, [dfn_o_data,uni_o_data,hpi_o_data], router1_data) == 1
    assert _verify_cert(ripe_o_data, [dfn_uni_hpi_o_data], router2_data) == 0
    assert _verify_cert(ripe_o_data, [dfn_uni_hpi_o_data], router3_data) == 0

def test_valid_chain():
    assert is_valid_chain(ripe_o_data, [], dfn_o_data) == True
    assert is_valid_chain(ripe_o_data, [dfn_o_data], uni_o_data) == True
    assert is_valid_chain(ripe_o_data, [], uni_o_data) == False
    assert is_valid_chain(ripe_o_data, [dfn_uni_hpi_o_data], router1_data) == True
    assert is_valid_chain(ripe_o_data, [dfn_o_data,uni_o_data,hpi_o_data], router1_data) == True
    assert is_valid_chain(ripe_o_data, [dfn_uni_hpi_o_data], router2_data) == False
    assert is_valid_chain(ripe_o_data, [dfn_uni_hpi_o_data], router3_data) == False

def test_valid_chain_from_path():
    assert is_valid_chain_from_path(ripe_o, None, dfn_o) == True
    assert is_valid_chain_from_path(ripe_o, dfn_o, uni_o) == True
    assert is_valid_chain_from_path(ripe_o, None, uni_o) == False
    assert is_valid_chain_from_path(ripe_o, dfn_uni_hpi_o, router1) == True
    assert is_valid_chain_from_path(ripe_o, dfn_uni_hpi_o, router2) == False
    assert is_valid_chain_from_path(ripe_o, dfn_uni_hpi_o, router3) == False

def test_signed_from_path_with_cert_from_path():
    assert _signed_from_path_with_cert_from_path(router1, signed_data_path, data) == 1
    assert _signed_from_path_with_cert_from_path(router2, signed_data_path, data) == 0
    assert _signed_from_path_with_cert_from_path(router3, signed_data_path, data) == 0

def test_signed_with_cert_from_path():
    assert _signed_with_cert_from_path(router1, signed_data, data) == 1
    assert _signed_with_cert_from_path(router2, signed_data, data) == 0
    assert _signed_with_cert_from_path(router3, signed_data, data) == 0

def test_has_signed():
    assert has_signed(router1_data, signed_data, data) == True
    assert has_signed(router2_data, signed_data, data) == False
    assert has_signed(router3_data, signed_data, data) == False


def test_has_signed_from_path():
    assert has_signed_from_path(router1, signed_data, data) == True
    assert has_signed_from_path(router2, signed_data, data) == False
    assert has_signed_from_path(router3, signed_data, data) == False


def run_tests():
    test_verify_cert_from_path()
    test_verify_cert()
    test_valid_chain()
    test_valid_chain_from_path()
    test_signed_from_path_with_cert_from_path()
    test_signed_with_cert_from_path()
    test_has_signed_from_path()
    test_has_signed()

