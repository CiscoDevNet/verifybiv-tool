# -*- coding: utf-8 -*-

# Copyright 2016, 2017 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
'''VerifySignature Library'''

__copyright__ = "2016, 2017 Cisco Systems, Inc."
__license__ = "Apache License, Version 2.0"
__author__ = ["James Aston", "Nicholas Brust", "Dwaine Gonyier", "others"]

import binascii
import re
import inspect
import logging
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
try:
    from Crypto.Hash import SHA1
except ImportError:
    from Crypto.Hash import SHA as SHA1
from Crypto.Util.asn1 import DerSequence

def _clean_eol(string):
    r'''Clean up embedded line endings in the supplied string to avoid later
    issues with regular expression matching of end-of-line markes ($) and so on.

    First pass replaces all occurrences of '\r\n' with '\n'. Then a second pass
    replaces any remaining '\r' with '\n'
    - string (str or unicode): A test string to clean up
    - returns: the cleaned up string'''

    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    return string.replace('\r\n', '\r').replace('\r', '\n')

def _pem_to_der(pem_body):
    '''Convert body of input PEM string from base64 text to DER format (binary)...

    Supplied string should not have PEM header or footer included.

    - pem_body (str): A text string containing the base64 encoded body of the
        certificate
    - returns: the body of certificate in DER (byte string) format'''
    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    return binascii.a2b_base64(''.join(pem_body.replace(" ", '').split()))

def _int_str_to_binary(int_str, bit_size):
    '''Convert a string containing a positive integer value to a zero padded byte
    string of specified size in bits.

    - int_str (str): The positive integer to convert as a string.
    - bit_size (int): The number of bits the byte string should contain
    - returns: a byte string representation of the integer'''
    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    assert int_str.isdigit(), "int_str should be a positive integer string"
    assert int(int_str) >= 0, "Supplied integer string should be zero or greater"

    return binascii.a2b_hex("{0:0{1}x}".format(int(int_str), int(bit_size) / 4))

def verifier_from_pem_stack(sudi_certstack_raw):
    '''Generate a verifier object from the supplied certificate PEM stack where
    the last certificate in the stack should be the SUDI public certificate.

    - sudi_certstack_raw (str): The PEM stack returned by the\n``show platform
        sudi certificate``\nIOS command
    '''
    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    # convert certificate from PEM format to DER format for processing by
    # pycrypto methods

    sudi_pubcert_der = _pem_to_der(extract_sudi_pubcert(sudi_certstack_raw))

    # get the public RSA key from the certificate
    cert = DerSequence()
    cert.decode(sudi_pubcert_der)
    tbs_cert = DerSequence()
    tbs_cert.decode(cert[0])
    subj_pub_key_info = tbs_cert[6]
    sudi_rsa_pubkey = RSA.importKey(subj_pub_key_info)

    # generate a signature verification object from the RSA public key
    sig_verifier = PKCS1_v1_5.new(sudi_rsa_pubkey)
    return sig_verifier

def extract_pem_cert_bodies(raw_pem_stack):
    '''Extract certificate bodies from input string containing PEM stack.

    The returned list contains the base64 encoded bodies of the certificates
    including newlines without the enclosing text headers and footers'''
    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    pat = (
        r'^-{5}BEGIN CERTIFICATE-{5}\s+'
        r'([a-zA-Z0-9/+=\s]+)\s+'
        r'-{5}END CERTIFICATE-{5}')

    return list(re.findall(pat, _clean_eol(raw_pem_stack), re.M))

def extract_sudi_pubcert(raw_pem_stack):
    '''Extract sudi public certificate body from input string containing PEM
    stack.

    Assumes the sudi pub cert is the last one in the stack.'''
    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    cert_pem_list = extract_pem_cert_bodies(raw_pem_stack)

    assert cert_pem_list.__len__() > 0, "No PEM certificates found in string"

    return cert_pem_list[-1]


def verify_show_platform_sudi(**kwargs):
    '''Validate the signed output of the ``show platform sudi certificate sign
    (nonce ###)`` command.

    This keyword should be used when the complete output of the\n``show platform
    sudi certificate sign (nonce ###)`` is avaiable. This keyword supports
    *Signature version 1* command output.

    The SUDI public certificate embedded in the output is used to verify the
    siganture in the output.

    Required keyword arguments:

    - nonce (str): nonce integer as string or ``None`` type for no nonce
    - output (str): The complete output of the ``show platform sudi certificate``
        IOS command as a string'''
    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    kwlist = [
        "nonce",
        "output"]
    for keyword in kwlist:
        assert kwargs.has_key(keyword), keyword + " required keyword argument not provided"

    output_ver1_pat = (
        r'Signature\s+version:\s+(?P<sigver>[0-9]+)\s+'
        r'Signature:\s+'
        r'(?P<signature>[0-9A-F]{512})'
        )

    # Parse output with sanity checks

    cert_pem_body_list = extract_pem_cert_bodies(kwargs['output'])

    assert cert_pem_body_list.__len__() > 0, "Did not find any PEM stack certificates"
    assert cert_pem_body_list.__len__() == 3, "Did not find three certificates in PEM stack"

    match = re.search(output_ver1_pat, kwargs['output'], re.M)
    assert match is not None, \
            "Unable to find Signature version 1 pattern in output"

    # Build binary data for verification
    sig_binary = binascii.a2b_hex(match.group('signature'))

    if kwargs['nonce'] is not None:
        nonce_binary = _int_str_to_binary(kwargs['nonce'], 64)
    else:
        nonce_binary = None

    sigver_binary = _int_str_to_binary(match.group('sigver'), 32)

    if nonce_binary is not None:
        data_binary = nonce_binary + sigver_binary
    else:
        data_binary = sigver_binary

    for pem_cert_item in cert_pem_body_list:
        data_binary += _pem_to_der(pem_cert_item)
    # Generate verifier object

    sig_verifier = verifier_from_pem_stack(kwargs['output'])

    # Verify binary data and return results

    data_binary_hash = SHA256.new(data_binary)
    data_binary_hash_old = SHA1.new(data_binary)

    # No easy way to determine hash algorithm from cert via Crypto library,
    # so try both SHA256 and SHA1 hashes.
    return sig_verifier.verify(data_binary_hash, sig_binary) or \
            sig_verifier.verify(data_binary_hash_old, sig_binary)

def get_expected_pcr_value(hash_list):
    '''Given a list of hash strings, calculate the expected PCR values

    For PCR0, extend by the Boot 0 hash and then the Boot Loader Hash
    For PCR8, extend by the OS hash

    Returns the calculated PCR value'''

    pcr_init = "0000000000000000000000000000000000000000000000000000000000000000"
    pcr_bin = binascii.a2b_hex(pcr_init)
    for hash_str in hash_list:
        hash_bin = binascii.a2b_hex(hash_str)
        hash_sha256_bin = SHA256.new(hash_bin).digest()
        pcr_bin = SHA256.new(pcr_bin + hash_sha256_bin).digest()

    return binascii.b2a_hex(pcr_bin).upper()


def verify_show_platform_integrity(**kwargs):
    '''Validate the signed output of the ``show platform integrity sign (nonce
    ###)`` command.

    This keyword should be used when the complete output of the\n``show platform
    integrity sign (nonce ###)`` is avaiable. This keyword supports *Signature
    version 1* command output.

    The output of the ``show platform sudi certificate`` is required since it
    contains the SUDI public certificate used to verify the signature.

    Required keyword arguments:

    - nonce (str): nonce integer as string or ``None`` type for no nonce
    - output (str): The complete output of the ``show platform integrity sign
        (nonce ###)`` IOS command as a string
    - show_sudi_cert (str): the complete output of the ``show platform sudi
        certificate`` IOS command as a string'''
    logging.debug(
        "Entering %s with parameters %s",
        inspect.currentframe().f_code.co_name, locals())

    kwlist = [
        "nonce",
        "output",
        "show_sudi_cert"]
    for keyword in kwlist:
        assert kwargs.has_key(keyword), keyword + " required keyword argument not provided"

    output_ver1_pat = (
        r'PCR0:\s+(?P<pcr0>[0-9A-F]{64})\s+'
        r'PCR8:\s+(?P<pcr8>[0-9A-F]{64})\s+'
        r'Signature\s+version:\s+(?P<sigver>[0-9]+)\s+'
        r'Signature:\s+'
        r'(?P<signature>[0-9A-F]{512})'
        )

    hash_dict = {
        'output_ver1_boot0_hash_pat':    r'Boot 0 Hash:\s+(?P<boot0hash>[0-9A-F]+)\s+',
        'output_ver1_bootldr_hash_pat':  r'Boot Loader Hash:\s+(?P<bootldrhash>[0-9A-F]+)\s+',
        'output_ver1_os_hash_pat':       r'OS Hash:\s+(?P<oshash>[0-9A-F]+)\s+'
    }

    # Parse output with sanity checks

    cert_pem_body_list = extract_pem_cert_bodies(kwargs['show_sudi_cert'])

    assert cert_pem_body_list.__len__() > 0, "Did not find any PEM stack certificates " + \
                "from show_sudi_cert value"
    assert cert_pem_body_list.__len__() == 3, "Did not find three certificates PEM in stack " +\
                "from show_sudi_cert value"

    match = re.search(output_ver1_pat, kwargs['output'], re.M)
    assert match is not None, \
            "Unable to find PCR registers and Signature version 1 pattern in output"

    hash_dict['match_boot0_hash'] = re.search(
        hash_dict['output_ver1_boot0_hash_pat'], kwargs['output'], re.M)
    assert hash_dict['match_boot0_hash'] is not None, \
            "Unable to find Boot 0 Hash pattern in output"

    hash_dict['match_bootldr_hash'] = re.search(
        hash_dict['output_ver1_bootldr_hash_pat'], kwargs['output'], re.M)
    assert hash_dict['match_bootldr_hash'] is not None, \
            "Unable to find Boot Loader Hash pattern in output"

    hash_dict['match_os_hash'] = re.search(
        hash_dict['output_ver1_os_hash_pat'], kwargs['output'], re.M)
    assert hash_dict['match_os_hash'] is not None, \
            "Unable to find OS Hash pattern in output"

    # Build binary data for verification
    sig_binary = binascii.a2b_hex(match.group('signature'))

    if kwargs['nonce'] is not None:
        nonce_binary = _int_str_to_binary(kwargs['nonce'], 64)
    else:
        nonce_binary = None

    sigver_binary = _int_str_to_binary(match.group('sigver'), 32)

    if nonce_binary is not None:
        data_binary = nonce_binary + sigver_binary
    else:
        data_binary = sigver_binary

    expected_pcr0 = get_expected_pcr_value([
        hash_dict['match_boot0_hash'].group('boot0hash'),
        hash_dict['match_bootldr_hash'].group('bootldrhash')])

    expected_pcr8 = get_expected_pcr_value([
        hash_dict['match_os_hash'].group('oshash')])

    assert expected_pcr0 == match.group('pcr0'), \
            "PCR0 does not match expected value of:\n{0}".format(expected_pcr0)
    assert expected_pcr8 == match.group('pcr8'), \
            "PCR8 does not match expected value of:\n{0}".format(expected_pcr8)

    #print "expected_pcr0:  " + expected_pcr0
    #print "expected_pcr8:  " + expected_pcr8

    # PCR register hashes
    pcr0_binary = binascii.a2b_hex(match.group('pcr0'))
    pcr8_binary = binascii.a2b_hex(match.group('pcr8'))

    if nonce_binary is not None:
        data_binary = nonce_binary + sigver_binary + pcr0_binary + pcr8_binary
    else:
        data_binary = sigver_binary + pcr0_binary + pcr8_binary

    # Generate verifier object

    sig_verifier = verifier_from_pem_stack(kwargs['show_sudi_cert'])

    # Verify binary data and return results

    data_binary_hash = SHA256.new(data_binary)
    data_binary_hash_old = SHA1.new(data_binary)

    # No easy way to determine hash algorithm from cert via Crypto library,
    # so try both SHA256 and SHA1 hashes.
    return sig_verifier.verify(data_binary_hash, sig_binary) or \
            sig_verifier.verify(data_binary_hash_old, sig_binary)

if __name__ == "__main__":
    print "Successful compile"
