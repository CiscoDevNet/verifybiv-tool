#!/usr/bin/python2.7
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

#####################################################################
# Minimum 100 character width console recommended
# On Windows, change pycrpto's folder name from crypto to Crypto

"""\
Verify Boot Integrity Visibility (BIV) of a system using the Secure Unique Identifier (SUDI).

Usage:
 VerifyBIV.py -s SUDI_FILE [-i SPI_FILE]
 VerifyBIV.py -h | --help
 VerifyBIV.py --version

Options:
 -h, --help                         Show this help message.
 --version                          Show version.
 -s SUDI_FILE, --sudi SUDI_FILE     Verify identity using file containing
                                    output of
                                    "show platform sudi certificate sign nonce XXXXX"
                                    including the cli cmd on the first line.
 -i SPI_FILE, --integrity SPI_FILE  Verify integrity using file containing
                                    output of
                                    "show platform integrity sign nonce XXXXX"
                                    including the cli cmd on the first line.
"""

__copyright__ = "2016, 2017 Cisco Systems, Inc."
__license__ = "Apache License, Version 2.0"
__author__ = ["James Aston", "Nicholas Brust", "Dwaine Gonyier", "others"]

import sys
from docopt import docopt
from VerifySignature import verify_show_platform_sudi
from VerifySignature import verify_show_platform_integrity


def get_contents(filename):
    """
    Read file and return first line as header and rest as body.

    Keyword arguments:
    filename -- path to file
    """
    with open(filename, 'r') as sig_file:
        header = sig_file.readline()
        body = sig_file.read()

    return header, body


def parse_sudi_info(header, body):
    """
    Parse SUDI_FILE for basic info and return
    nonce, number of certs, signature version and signature.

    Keyword arguments:
    header -- first line of SPI_FILE containing cli cmd, return value of get_contents()
    body -- rest of SPI_FILE, return value of get_contents()
    """

    try:
        nonce = header.split()[6]
        cert_count = len(body.split('BEGIN CERT')) - 1
        sig_ver = body.split('Signature version: ')[1][0]
        signature = body.split('Signature:')[1].split()[0]
    except BaseException as err:
        print "\tParse SUDI", str(err.__class__).split("'")[1::2][0] + ":"
        print "\t", err.message
        print """
\tInvalid SUDI_FILE format. Confirm file is exact output of
\t'show platform sudi certificate sign nonce XXXXX'
\tincluding cli command on first line."""
        sys.exit(-1)

    return nonce, cert_count, sig_ver, signature


def parse_spi_info(header, body):
    """
    Parse SPI_FILE for basic info and return
    nonce, pcr0, pcr8, signature version and signature.

    Keyword arguments:
    header -- first line of SPI_FILE containing cli cmd, return value of get_contents()
    body -- rest of SPI_FILE, return value of get_contents()
    """

    try:
        nonce = header.split()[5]
        pcr0 = body.split('PCR0: ')[1].split()[0]
        pcr8 = body.split('PCR8: ')[1].split()[0]
        sig_ver = body.split('Signature version: ')[1][0]
        signature = body.split('Signature:')[1].split()[0]
    except BaseException as err:
        print "\tParse SPI", str(err.__class__).split("'")[1::2][0] + ":"
        print "\t", err.message
        print """
\tInvalid SPI_FILE format. Confirm file is exact output of
\t'show platform integrity sign nonce XXXXX'
\tincluding cli command on first line."""
        sys.exit(-1)

    return nonce, pcr0, pcr8, sig_ver, signature


def print_signature(signature):
    """
    Print large signature in multi-line format for readability.
    Print 64 characters per line.

    Keyword arguments:
    signature -- signature, return value of parse_sudi_info() or parse_spi_info()
    """

    # split signature into 64 character pieces
    chunks, chunk_size = len(signature), 64
    chunked = [signature[i:i+chunk_size] for i in range(0, chunks, chunk_size)]

    # print signature
    for count, line in enumerate(chunked):
        if count == 0:
            print "\tSignature:\n\t\t", line
        else:
            print "\t\t", line


def main(args):
    """
    Verify identity and integrity of a system using the Secure Unique Identifier (SUDI).
    Print message(s) conveying verification success or failure.

    Keyword arguments:
    args -- provided commandline argurments
    """

    # read args
    sudi_file = args['--sudi']
    spi_file = args['--integrity']

    print "\nGathering identity info...\n"
    header, body = get_contents(sudi_file)

    # show basic identity info
    nonce, cert_count, sig_ver, signature = parse_sudi_info(header, body)
    print "\tNonce:\t\t", nonce
    print "\tCertificates Found:\t", cert_count
    print "\tSignature Version:\t", sig_ver
    print_signature(signature)

    # verify identity
    print "\nVerifying platform identity signature..."
    try:
        result = verify_show_platform_sudi(nonce=nonce, output=body)
    except BaseException as err:
        result = False
        print "\n\tVerify identity", str(err.__class__).split("'")[1::2][0] + ":"
        print "\t", err.message

    print "\n\tPlatform identity verification:\t\t", "SUCCESSFUL" if result else "FAILED", "\n"

    # exit upon failure
    if result is False:
        sys.exit(-1)

    # use SPI_FILE if available
    if spi_file is not None:
        print "\nGathering integrity info...\n"
        header, body = get_contents(spi_file)

        # show basic integrity info
        nonce, pcr0, pcr8, sig_ver, signature = parse_spi_info(header, body)
        print "\tNonce:\t", nonce
        print "\tPCR0:\t", pcr0
        print "\tPCR8:\t", pcr8
        print "\tSignature Version:\t", sig_ver
        print_signature(signature)

        # verify integrity
        print "\nVerifying platform integrity signature..."
        header, sudi = get_contents(sudi_file)

        try:
            result = verify_show_platform_integrity(nonce=nonce, output=body, show_sudi_cert=sudi)
        except BaseException as err:
            result = False
            print "\n\tVerify Integrity", str(err.__class__).split("'")[1::2][0] + ":"
            print "\t", err.message

        print "\n\tPlatform integrity verification:\t", "SUCCESSFUL" if result else "FAILED", "\n"

    # exit upon failure
    if result is False:
        sys.exit(-1)


if __name__ == "__main__":
    main(docopt(__doc__, version='0.3.0'))
