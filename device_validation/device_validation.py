#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Reference model for validating the
Secure Identity and Proof of Possession
of the private key for a given device.
This script supports two methods to execute
the validations: PNP API and CLI.
"""
###############################################
#
# File Name: device_validation.py
#
# Version: v1.1
#
# Sample Device Validation Script
#
# THIS SCRIPT IS FOR REFERENCE PURPOSES ONLY!
# THIS SCRIPT IS FOR REFERENCE PURPOSES ONLY!
# THIS SCRIPT IS FOR REFERENCE PURPOSES ONLY!
#
# Purpose: Reference model for validating the
#      Secure Identity and Proof of Possession
#      of the private key for a given device.
#      This script supports two methods to execute
#      the validations: PNP API and CLI.
#
# Requirements:
#   PNP API:
#      For PNP API method to work properly
#      the device must have the PNP listener enabled.
#   Assumption: The PNP API credentials match the
#      SSH login credentials.
#
#   CLI:
#      For the CLI method to work properly the
#      device must support the 'show platform sudi...'
#      command (currently only in S-train).
#
# Input (devices.csv):
#   A comma seperated file (csv) is used for input to
#   determine which devices are to be examined. Each
#   record in the file must contain at least 4 or 5 fields:
#      For PNP:
#       - ip address of device
#       - method ("PNP" or "CLI")
#       - admin user id
#       - admin password
#       - UDI (optional)
#       - SUDI serial (optional)
#
#      For CLI:
#       - ip address of device
#       - method ("PNP" or "CLI")
#       - admin user id
#       - admin password
#       - enable password
#       - SUDI serial (optional)
#
#   For the optional fields, if they are missing, the
#   script will retrieve those data items from the device.
#   The retrieved values will be written out to the output file.
#
# Output (devices.csv, devices.old.csv <-- original input file):
#   An output file is created and overwrites the existing input file.
#   The new output file will contain any data that was collected from the
#   device which was missing prior (UDI, SUDI Serial).
#   The original input file will be renamed as .old.csv to keep for reference.
#
# Usage:
#   To validate all the devices listed in the input file:
#      ./device_validation.py
#
#   To validate a single device in the input file:
#      ./device_validation.py <ip address>
#
# Dependencies:
#   The python dependencies are as follows:
#        os, csv, requests, base64, string, random, struct
#        argparse, pexpect, binascii, xml.etree, OpenSSL, six
#   If any of these packages are missing, use your python package
#   installer to install them on your system.
#   This script was tested against python 2.7. Any other version is
#   untested and may not work as expected.
#
# Disclaimer:
#   This script is a demo tool and is unsupported. No guarantees or warranties
#   are implied. A modest effort was made to error check the various steps
#   but there are no guarantees that all error scenarios have been covered.
#
# Change Log:
#   V1.1 - added Product ID(PID) checking
#
# Copyright 2016, 2018 Cisco Systems, Inc. All Rights Reserved
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

###############################################

import os
import csv
import base64
import string
import random
import argparse
import binascii
from xml.etree import ElementTree
from OpenSSL import crypto
from six import b
import pexpect
import requests

##
# File containing the devices to authenticate
##
DEVICE_FILE = 'devices.csv'
OLD_DEVICE_FILE = 'devices.old.csv'
OUTPUT_FILE = 'validated_output_devices.csv'

##
# constants
##
UNKNOWN_STR = "Uknown"


##
# trusted certificate chain
##
TRUST_CHAIN_PEM1 = b("""-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIQX/h7KCtU3I1CoxW1aMmt/zANBgkqhkiG9w0BAQUFADA1
MRYwFAYDVQQKEw1DaXNjbyBTeXN0ZW1zMRswGQYDVQQDExJDaXNjbyBSb290IENB
IDIwNDgwHhcNMDQwNTE0MjAxNzEyWhcNMjkwNTE0MjAyNTQyWjA1MRYwFAYDVQQK
Ew1DaXNjbyBTeXN0ZW1zMRswGQYDVQQDExJDaXNjbyBSb290IENBIDIwNDgwggEg
MA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQCwmrmrp68Kd6ficba0ZmKUeIhH
xmJVhEAyv8CrLqUccda8bnuoqrpu0hWISEWdovyD0My5jOAmaHBKeN8hF570YQXJ
FcjPFto1YYmUQ6iEqDGYeJu5Tm8sUxJszR2tKyS7McQr/4NEb7Y9JHcJ6r8qqB9q
VvYgDxFUl4F1pyXOWWqCZe+36ufijXWLbvLdT6ZeYpzPEApk0E5tzivMW/VgpSdH
jWn0f84bcN5wGyDWbs2mAag8EtKpP6BrXruOIIt6keO1aO6g58QBdKhTCytKmg9l
Eg6CTY5j/e/rmxrbU6YTYK/CfdfHbBcl1HP7R2RQgYCUTOG/rksc35LtLgXfAgED
o1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJ/PI
FR5umgIJFq0roIlgX9p7L6owEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQEF
BQADggEBAJ2dhISjQal8dwy3U8pORFBi71R803UXHOjgxkhLtv5MOhmBVrBW7hmW
Yqpao2TB9k5UM8Z3/sUcuuVdJcr18JOagxEu5sv4dEX+5wW4q+ffy0vhN4TauYuX
cB7w4ovXsNgOnbFp1iqRe6lJT37mjpXYgyc81WhJDtSd9i7rp77rMKSsH0T8lasz
Bvt9YAretIpjsJyp8qS5UwGH0GikJ3+r/+n6yUA4iGe0OcaEb1fJU9u6ju7AQ7L4
CYNu/2bPPu8Xs1gYJQk0XuPL1hS27PKSb3TkL4Eq1ZKR4OCXPDJoBYVL0fdX4lId
kxpUnwVwwEpxYB5DC2Ae/qPOgRnhCzU=
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM2 = b("""-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIQLtIOc0fTM4NLT90N17aWfjANBgkqhkiG9w0BAQUFADAr
MQ4wDAYDVQQKEwVDaXNjbzEZMBcGA1UEAxMQQ2lzY28gUm9vdCBDQSBNMTAeFw0w
ODExMTgyMTUwMjRaFw0zMzExMTgyMTU5NDZaMCsxDjAMBgNVBAoTBUNpc2NvMRkw
FwYDVQQDExBDaXNjbyBSb290IENBIE0xMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0A
MIIBCAKCAQEAmkHcGd1JapBbD5HUaP1uWJRecjN1sKi6R+aqLf/Ksu0msyMPf6so
mnNI6LAyRUiE06Pmfq0QhZHPv8rVjKJzCbYTEW6FwYpz2XfjW2zDoaGyOcX1FBfe
d8Ijrd+dGwcGtx7x7kr9fLNQUBfsDmr+Q7sx5tWX1IqXVwnzh1tx/YRNKtaZaX0D
dy4qHPhb5FX1r4YMfADu4Igw3RjS8KCQ2FwAY9/PsrPbyQnhKsh8Pbw1ewnpcJ6E
p1BVYIQyCWOVdjVLbW4Sjpds0uggxs4UU/VQjGmgrag1PIKFWocWoIGTzaTHkiNw
L0VYiD3iBguBU5ABhsPklUrj6xk0Hau8DwIBA6NRME8wCwYDVR0PBAQDAgGGMA8G
A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKYDHX/KvbKRQMbLgjYfa5iP3bwpMBAG
CSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBBQUAA4IBAQB+bX5hHtoBnp84Yb3n
X4LpXH+84R1sUKB3W+inWD0xd59fmzwMsySsxzzrwMbhnvbS7C17H9aT2U9dUdPU
T56pg+eX9s4XEaGL1FedlHk6G3FL9dvmwKHuW3uTmZTizjPPy3hElpUQVcNGesi1
uI001tPCVVBUo7tlyfhQk6ztuk3wuoHvH/gDPVZxKbWESHDxCCkZxDnLQdHpJ0W1
4SVrT/7NmFcd8w/RyqTRIxuUy2UQNEeaioEFQ5g+bZh3oI3V7Y1d/I3HLQVoBWkv
bykggZS7q4YJyt5vOAqrI0kFgqPrzI6dRqVL5mAP1gAwXrOOvtdErDLH6EHnRu41
vdR2
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM3 = b("""-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIBATANBgkqhkiG9w0BAQsFADArMQ4wDAYDVQQKEwVDaXNj
bzEZMBcGA1UEAxMQQ2lzY28gUm9vdCBDQSBNMjAeFw0xMjExMTIxMzAwMThaFw0z
NzExMTIxMzAwMThaMCsxDjAMBgNVBAoTBUNpc2NvMRkwFwYDVQQDExBDaXNjbyBS
b290IENBIE0yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2AYlIRNP
jTp1fOk9yHRBO02gZfnCv5SE72sLcYfUWMJgMiy6zLq7YzTbsxJCanmFhrPof8mS
i+OnN0XTlINoZSDbitRDQd/KTNTXEM1oJ5VyTnRKVPXacemlr00MsWwx+wzec4Ka
UAleDuM1vrpOwsrgbsiELYqz7pLsBILkx25NGLXpZMtkhtLwuOFZFjqmJkgF7mMp
HhWD7x55wYIAKdRWjwptwshYOS1juHGAOuHc67MTUiIFUUcAiIdt7dE817jahXkk
xipdHfKDTYEfp83UGY6raUDm+wcK8o5lPm3lPcEy7gYmLey7HrFFYlEr8FkXMXIa
zAB0wwy7hMpzrQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQUyQD5H4ofwma9pdJtZQ4iLjTDBaAwDQYJKoZIhvcNAQEL
BQADggEBAHq+PI0n6M3kkhymizBuwdnWiRrDwJl19061gsiVIlm3oKhQjlkZC28W
2Q/yGSdNUE3e9G0M5nRcdPFEf4KSvFxe47N+JaOLuRA8a11dPmk73Khb7afCuujC
92jLKItwcpHPLD+6dVlzM1IZgpTtcJ7SZxR2MRsmpqn5fnsZtuKnUqLUU+pvhngz
B8Hefd8V0D1soiW8xzLwSXtt8jBmm9kUXbYPpWxbkmuGtBMEh2P1fWmuImJsdnKS
mvMFXmYz5Zcg4A15NG8xHVhezeAlwcOl3RDczn6V9ttEp13GcZLPoYH68I3pptmS
w+Twrdtsr+6t2osJSvvaKp6YFlAHf4c=
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM4 = b("""-----BEGIN CERTIFICATE-----
MIIBzDCCAVKgAwIBAgIBATAKBggqhkjOPQQDAzAsMQ4wDAYDVQQKEwVDaXNjbzEa
MBgGA1UEAxMRQ2lzY28gRUNDIFJvb3QgQ0EwJBcNMTMwNDA0MDgxNTQ0WhgTMjA1
MzA0MDQwODE1NDQuNzA0WjAsMQ4wDAYDVQQKEwVDaXNjbzEaMBgGA1UEAxMRQ2lz
Y28gRUNDIFJvb3QgQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR+wMO82BvG82eR
TdZ4jOa1dTkEfy/+YNCsdyrTbQJBRVRnsFi3Gb/MvUs2XHtbgzjsptdNMCZhs0uL
q14OFSY7TIirAnDJIjcCUHXA1dRINMe/WFP+rsuPcyD1BlsSh8qjQjBAMA4GA1Ud
DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSkRbYvozGxdhWw
ChgzyvatTz0oBDAKBggqhkjOPQQDAwNoADBlAjBjQV1EkwWv8BoBdCqlZWGX3uc7
SWDYFm3QXSyzDj9gWoN27S2akLlf6EWzBFCYGb8CMQDZqDfu14x4lefS/hbxP2PX
EBiqvFYLAZYLy8hCn59xkByPRZdVhNgGJIWlt4XdwwM=
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM5 = b("""-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM6 = b("""-----BEGIN CERTIFICATE-----
MIIE2TCCA8GgAwIBAgIKamlnswAAAAAAAzANBgkqhkiG9w0BAQUFADA1MRYwFAYD
VQQKEw1DaXNjbyBTeXN0ZW1zMRswGQYDVQQDExJDaXNjbyBSb290IENBIDIwNDgw
HhcNMDUwNjEwMjIxNjAxWhcNMjkwNTE0MjAyNTQyWjA5MRYwFAYDVQQKEw1DaXNj
byBTeXN0ZW1zMR8wHQYDVQQDExZDaXNjbyBNYW51ZmFjdHVyaW5nIENBMIIBIDAN
BgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAoMX33JaUNRXx9JlOu5tB4X3beRaR
u/NU8kFKlDJiYskj95rnu5t56AcpTjD1rhvFIVZGsPj05o6BuBbMqJuF0kKB23zL
lKkRYRIcXOozIByaFqd925kGauI2r+z4Cv+YZwf0MO6l+IgaqujHPBzO7kj9zVw3
8YaTnj1xdX007ksUqcApewUQ74eeaTEw9Ug2P9irzhXi6FifPmJxBIcmpBViASWq
1d/JyVu4yaEHe75okpOTIKhsvRV100RdRUvsqNpgx9jI1cjtQeH1X1eOUzKTSdXZ
D/g2qgfEMkHFp68dGf/2c5k5WnNnYhM0DR9elXBSZBcG7FNcXNtq6jUAQQIBA6OC
AecwggHjMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFNDFIiarT0Zg7K4F
kcfcWtGwR/dsMAsGA1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADAZBgkrBgEE
AYI3FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQn88gVHm6aAgkWrSugiWBf
2nsvqjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vd3d3LmNpc2NvLmNvbS9zZWN1
cml0eS9wa2kvY3JsL2NyY2EyMDQ4LmNybDBQBggrBgEFBQcBAQREMEIwQAYIKwYB
BQUHMAKGNGh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3VyaXR5L3BraS9jZXJ0cy9j
cmNhMjA0OC5jZXIwXAYDVR0gBFUwUzBRBgorBgEEAQkVAQIAMEMwQQYIKwYBBQUH
AgEWNWh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3VyaXR5L3BraS9wb2xpY2llcy9p
bmRleC5odG1sMF4GA1UdJQRXMFUGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUH
AwUGCCsGAQUFBwMGBggrBgEFBQcDBwYKKwYBBAGCNwoDAQYKKwYBBAGCNxQCAQYJ
KwYBBAGCNxUGMA0GCSqGSIb3DQEBBQUAA4IBAQAw8zAtjPLKN0pkmSQpCvKGqkLV
I+ii6itvaSN6go4cTAnPpE+rhC836WVg0ZrG2PML9d7QJwBcbx2RvdFOWFEdyeP3
OOfTC9Fovo4ipUsG4eakqjN9GnW6JvNwxmEApcN5JlunGdGTjaubEBEpH6GC/f08
S25l3JNFBemvM2tnIwcGhiLa69yHz1khQhrpz3B1iOAkPV19TpY4gJfVb/Cbcdi6
YBmlsGGGrd1lZva5J6LuL2GbuqEwYf2+rDUU+bgtlwavw+9tzD0865XpgdOKXrbO
+nmka9eiV2TEP0zJ2+iC7AFm1BCIolblPFft6QKoSJFjB6thJksaE5/k3Npf
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM7 = b("""-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIBAjANBgkqhkiG9w0BAQsFADArMQ4wDAYDVQQKEwVDaXNj
bzEZMBcGA1UEAxMQQ2lzY28gUm9vdCBDQSBNMjAeFw0xMjExMTIxMzUwNThaFw0z
NzExMTIxMzAwMTdaMDYxDjAMBgNVBAoTBUNpc2NvMSQwIgYDVQQDExtDaXNjbyBN
YW51ZmFjdHVyaW5nIENBIFNIQTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQD0NktCAjJn3kk98hU7wUVp6QlOFrlItEce6CpbfYpeLdUeZduAo+S0otzT
lJwS2BlMhZtacu9vUpfmW9w7nQo9zVT3eyPuhF/6/9TEdVBn75zb5CfV+E6ld+fH
nuPiFyBu+HDDJRd373Op+957IdoWyPvD8hHR1HJGFJ3JJKBg0UScL4JCwleu98Xq
/yPlAqBhExa7a2/fqSmZA0vZIG1bBfWZY8ZtSeTxKg3eWynV+xElabHqTDMYWf+2
obs4YB5lINTbYgHyRETP6T8Xr6TtD0h3654OUHcW+1meBu/jctluMKppeSjVtrof
5vt+pbkCg0iQAAjsL0qczT3yaNXvAgMBAAGjggGHMIIBgzAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBADBcBgNVHSAEVTBTMFEGCisGAQQBCRUBEgAw
QzBBBggrBgEFBQcCARY1aHR0cDovL3d3dy5jaXNjby5jb20vc2VjdXJpdHkvcGtp
L3BvbGljaWVzL2luZGV4Lmh0bWwwHQYDVR0OBBYEFHrXeZXKu0gruFUU/aPAD7yn
D5YZMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3Vy
aXR5L3BraS9jcmwvY3JjYW0yLmNybDB8BggrBgEFBQcBAQRwMG4wPgYIKwYBBQUH
MAKGMmh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3VyaXR5L3BraS9jZXJ0cy9jcmNh
bTIuY2VyMCwGCCsGAQUFBzABhiBodHRwczovL3Rvb2xzLmNpc2NvLmNvbS9wa2kv
b2NzcDAfBgNVHSMEGDAWgBTJAPkfih/CZr2l0m1lDiIuNMMFoDANBgkqhkiG9w0B
AQsFAAOCAQEAc1k2rH6YT4juFxs9q7ObzfcKbNvOyDsaU7av4IHFXmn/JxfnBmUv
YxAI2Hx3xRb0KtG1JGkffQjVAtBboTXynLaQso/jj46ZOubIF8y6Ho3nTAv7Q6VH
kqSCdZClVu91zbHV9FFYQzJxjw1QgB0a4ItS4yhdmgl3oDNEcb3trQezrQ3/857/
ISqBGVLEbKHOu8H6zOLhxAgZ08ae1oQQQJowki0Ibd+LRLGovtEwLg8yyqiTIGve
7VFL2sRa8Z3rK9tlwKVH2kpFKNAeN3rfKFqr0/weR0cyKpmLMrSBTBZcxQcJCYF4
X6FO/32KOqcxJFIOKGVIUjvAvioOqoducw==
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM8 = b("""-----BEGIN CERTIFICATE-----
MIIDFTCCApugAwIBAgIBAjAKBggqhkjOPQQDAzAsMQ4wDAYDVQQKEwVDaXNjbzEa
MBgGA1UEAxMRQ2lzY28gRUNDIFJvb3QgQ0EwJBcNMTMwNDA0MDgyNjEzWhgTMjA1
MzA0MDQwODE1NDMuNzA0WjArMQ4wDAYDVQQKEwVDaXNjbzEZMBcGA1UEAxMQQUNU
MiBFQ0MgU1VESSBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIxh3Pp50jEK+M7g
Ecw8Rxekw4ve3+3hqknQyuZorFaaAT9DcMHJms7Phk4k/lLOdvwSrqOCZWme+HJ5
c8wSJ5D8LbmoNm10gnmFSYXAd7Fblb2IkilRItTiIMfOXbV3cKOCAYowggGGMA4G
A1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMFwGA1UdIARVMFMwUQYK
KwYBBAEJFQETADBDMEEGCCsGAQUFBwIBFjVodHRwOi8vd3d3LmNpc2NvLmNvbS9z
ZWN1cml0eS9wa2kvcG9saWNpZXMvaW5kZXguaHRtbDAdBgNVHQ4EFgQUloc62ImB
kUEVM7/gNI8gj8K7w5YwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL3d3dy5jaXNj
by5jb20vc2VjdXJpdHkvcGtpL2NybC9lY2Nyb290LmNybDB+BggrBgEFBQcBAQRy
MHAwPwYIKwYBBQUHMAKGM2h0dHA6Ly93d3cuY2lzY28uY29tL3NlY3VyaXR5L3Br
aS9jZXJ0cy9lY2Nyb290LmNlcjAtBggrBgEFBQcwAYYhaHR0cHM6Ly9wa2ljdnMu
Y2lzY28uY29tL3BraS9vY3NwMB8GA1UdIwQYMBaAFKRFti+jMbF2FbAKGDPK9q1P
PSgEMAoGCCqGSM49BAMDA2gAMGUCMQDtD7/BBY0CM5KffW1MrHJYZNUcRiI0z55Y
+kEiRKeazDjfJnsr2U4MGd7DtcslHAsCMDzFL8VaI91AqODM+tVuffOyvnpNYR/k
CUyCAI91nrf8NOuEaaLakMmf6LRZoxdchw==
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM9 = b("""-----BEGIN CERTIFICATE-----
MIIEPDCCAySgAwIBAgIKYQlufQAAAAAADDANBgkqhkiG9w0BAQUFADA1MRYwFAYD
VQQKEw1DaXNjbyBTeXN0ZW1zMRswGQYDVQQDExJDaXNjbyBSb290IENBIDIwNDgw
HhcNMTEwNjMwMTc1NjU3WhcNMjkwNTE0MjAyNTQyWjAnMQ4wDAYDVQQKEwVDaXNj
bzEVMBMGA1UEAxMMQUNUMiBTVURJIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA0m5l3THIxA9tN/hS5qR/6UZRpdd+9aE2JbFkNjht6gfHKd477AkS
5XAtUs5oxDYVt/zEbslZq3+LR6qrqKKQVu6JYvH05UYLBqCj38s76NLk53905Wzp
9pRcmRCPuX+a6tHF/qRuOiJ44mdeDYZo3qPCpxzprWJDPclM4iYKHumMQMqmgmg+
xghHIooWS80BOcdiynEbeP5rZ7qRuewKMpl1TiI3WdBNjZjnpfjg66F+P4SaDkGb
BXdGj13oVeF+EyFWLrFjj97fL2+8oauV43Qrvnf3d/GfqXj7ew+z/sXlXtEOjSXJ
URsyMEj53Rdd9tJwHky8neapszS+r+kdVQIDAQABo4IBWjCCAVYwCwYDVR0PBAQD
AgHGMB0GA1UdDgQWBBRI2PHxwnDVW7t8cwmTr7i4MAP4fzAfBgNVHSMEGDAWgBQn
88gVHm6aAgkWrSugiWBf2nsvqjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vd3d3
LmNpc2NvLmNvbS9zZWN1cml0eS9wa2kvY3JsL2NyY2EyMDQ4LmNybDBQBggrBgEF
BQcBAQREMEIwQAYIKwYBBQUHMAKGNGh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3Vy
aXR5L3BraS9jZXJ0cy9jcmNhMjA0OC5jZXIwXAYDVR0gBFUwUzBRBgorBgEEAQkV
AQwAMEMwQQYIKwYBBQUHAgEWNWh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3VyaXR5
L3BraS9wb2xpY2llcy9pbmRleC5odG1sMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJ
KoZIhvcNAQEFBQADggEBAGh1qclr9tx4hzWgDERm371yeuEmqcIfi9b9+GbMSJbi
ZHc/CcCl0lJu0a9zTXA9w47H9/t6leduGxb4WeLxcwCiUgvFtCa51Iklt8nNbcKY
/4dw1ex+7amATUQO4QggIE67wVIPu6bgAE3Ja/nRS3xKYSnj8H5TehimBSv6TECi
i5jUhOWryAK4dVo8hCjkjEkzu3ufBTJapnv89g9OE+H3VKM4L+/KdkUO+52djFKn
hyl47d7cZR4DY4LIuFM2P1As8YyjzoNpK/urSRI14WdIlplR1nH7KNDl5618yfVP
0IFJZBGrooCRBjOSwFv8cpWCbmWdPaCQT2nwIjTfY8c=
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM10 = b("""-----BEGIN CERTIFICATE-----
MIIFBTCCA+2gAwIBAgIRANAeR0AAAAERw4qWRAAAAAIwDQYJKoZIhvcNAQEFBQAw
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzAeFw0wNzA0MDUyMDU4MzFaFw0xMjA0MDUyMDU4MzFa
MC0xFjAUBgNVBAoTDUNpc2NvIFN5c3RlbXMxEzARBgNVBAMTCkNpc2NvIFNTQ0Ew
ggEgMA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQC+g31JNPoDO/pVjP0QwWIh
hgS7Cq4qhXLtlIdbIRVIuv5if0mqThqKAgr5P7D0fMzXDy10z71BWTw/pMYuCLo/
bZO6o6Hr2xfk/hwJ6T+uQooNpwgE7e2ZPvHVRS3jeyFTfF2nPfA0WV4XZO3u/GOD
l6XwdN7DVxLETLsU2e+tEZ9uSeJEA1kvCXjIyFYalJggCF/8FSJHuEQDtYquq3TW
GzJeq/rngUg3tse/N7E4HTLuK2G9KqJq8rtWyW/ve5F723Il/KtARTLh98eqIylG
RHSu6UZgYbXNu+p0jHqPtDlEQ4YntRhvWUMA0/2FbXpcisd8B5oiVpCORQAb+1Pb
AgEDo4ICDjCCAgowDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
XAYDVR0gBFUwUzBRBgorBgEEAQkVAQEAMEMwQQYIKwYBBQUHAgEWNWh0dHA6Ly93
d3cuY2lzY28uY29tL3NlY3VyaXR5L3BraS9wb2xpY2llcy9pbmRleC5odG1sMB0G
A1UdDgQWBBQW4baHahd8OiO2Pr9wD0uY71dciDA5BgNVHR8EMjAwMC6gLKAqhiho
dHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDMuY3JsMHQGCCsGAQUF
BwEBBGgwZjAnBggrBgEFBQcwAYYbaHR0cDovL29jc3B0cy5pZGVudHJ1c3QuY29t
MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1c3QuY29tL3Jvb3RzL0RT
VFJPT1RDQVgzLmNlcjCBlAYDVR0lBIGMMIGJBggrBgEFBQcDAQYIKwYBBQUHAwIG
CCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUFBwMGBggrBgEFBQcD
BwYIKwYBBQUHAwgGCCsGAQUFBwMJBgorBgEEAYI3CgMBBgorBgEEAYI3CgMJBgor
BgEEAYI3FAIBBgkrBgEEAYI3FQYwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/E
FWCFiRAwDQYJKoZIhvcNAQEFBQADggEBAA/rMhwFqiBXguJOxEK25GJd7Y4IA+Ij
NpZErhyCFVRMBtLEr0NFGXamXZ7zLHNXvTNXysPxPsC1Y5sMN7Q7A8IQ6VrASdff
deBuzixLGqp4szuMz5oDDBIdW7fAOeYtBCNGnHZvuWOnd4Svh+IW5Pu8w31v2chK
LfeVXHMvLkXU9ukMeN2J0G4RzY/xatcrnKCCtrHZZBjV4zh9+DQOmtDllH2/vo0/
tGBqYtcRU8ugzl7AcUTZVLtSts4VkBfCieJvxZ/b1hwvJ40UZMH9IMl2E1yMH9W5
ystWvB+EpH892DLJqjqma/WJ7tLva7egyvQ7shZ0xDgx0nswy8QfFEA=
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM11 = b("""-----BEGIN CERTIFICATE-----
MIIFBzCCA++gAwIBAgIQCgFBQgAAASvQQLRnAAAAAjANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTEwMTAyMTE5MjUyMloXDTE1MTAyMjE5MjUyMlow
LjEWMBQGA1UEChMNQ2lzY28gU3lzdGVtczEUMBIGA1UEAxMLQ2lzY28gU1NDQTIw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDR8snfOEhLUveeHkflToCJ
xGkNgp/66Fqx35tpgQigm4ZOP+oIB21H9VyAHwIY5eGJELYH5Zc8o1sdjquA2Qt4
bV5bgVLB+aOFkaimFfZIfMtJjCuqWjit8d2OD2I0VUN6k9LJePpSdQEUsCsEgPpz
cXouYfVK2A1ZiYfB6WnHTleAab8McdTn0j3593uXXLHQdtSPpl1tJdnPOsWf1yXs
3t7n3MesUgXtsUit59SbSuO6+CyfsD6En1agFHoKre6MMgEvNxKr4AqtILvsC8fy
k98n5yA8EAycgp5XI9pL86cWrwOj23xGUnKNoUIyMUdaWhcMeyDP2XI07XYpg1ER
AgMBAAGjggIOMIICCjAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIB
ADBcBgNVHSAEVTBTMFEGCisGAQQBCRUBAQAwQzBBBggrBgEFBQcCARY1aHR0cDov
L3d3dy5jaXNjby5jb20vc2VjdXJpdHkvcGtpL3BvbGljaWVzL2luZGV4Lmh0bWww
HQYDVR0OBBYEFMewEAgv8BhfH5BKSypHqgtXX6S7MDkGA1UdHwQyMDAwLqAsoCqG
KGh0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9EU1RST09UQ0FYMy5jcmwwdAYIKwYB
BQUHAQEEaDBmMCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcHRzLmlkZW50cnVzdC5j
b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv
RFNUUk9PVENBWDMuY2VyMIGUBgNVHSUEgYwwgYkGCCsGAQUFBwMBBggrBgEFBQcD
AgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUF
BwMHBggrBgEFBQcDCAYIKwYBBQUHAwkGCisGAQQBgjcKAwEGCisGAQQBgjcKAwkG
CisGAQQBgjcUAgEGCSsGAQQBgjcVBjAfBgNVHSMEGDAWgBTEp7Gkeyxx+tvhS5B1
/8QVYIWJEDANBgkqhkiG9w0BAQUFAAOCAQEAvrBuXbGT4vxVdWhrj+Oejp/8cKyb
gg5G+ZV07o2MPTvuYTmEfz2v3k2mXAXF46iMYVj5xw8NdPaxcip/Q5xdQNiXTn40
ySnWHKXHLcCAFa7/MOKnICY0FL4BnOp0w8fDtighl9rMaOWw4ycExvYrXM5HJrch
FG4NdKruyWiTtAGLZ6j6VmuATlJP10qnmAOrj8NngA9Act87oLMxiQte+viqu1fT
3Vi4odHZv1Y3WZUR7grQaWEyfQHEuj2A0GrHIlmCJiCFfLcZSjcKSOXbgnfvna8z
5nIbIZIwxFsuxXDOELhmZJY1dmuqUyxKTQOhrtLwkTk5fkizGJJPmezuZg==
-----END CERTIFICATE-----
""")

TRUST_CHAIN_PEM12 = b("""-----BEGIN CERTIFICATE-----
MIIFzDCCBLSgAwIBAgIQCgFBQgAAAUFcf/EVAAAAAjANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTEzMDkyNjIyNTk1MFoXDTE4MDkyNjIyNTk1MFow
OzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUNpc2NvIFN5c3RlbXMxFDASBgNVBAMT
C0Npc2NvIFNTQ0EzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlPoD
SU2Cp297a/eGs1+D9yh/5c7po+Yog/fNSvhoWxMfM2NxwiP9KxHAXFXEoCpySlG7
KSU+lcfkEJeK0ZUHlPeuz3aSkihyETCObX8PSYslGhpRw2V5iEZNPKyVFsWC8BQN
mGtffs7myzVBHTIHTgGdt27qsf+LI5M19bJPMs5Tih2+NhXOn5WL5V+JrTPHjCAg
d2Qb7GjbBwUlSmA3UkXyvEmrhDIOm2k8q4oqMSYGn9Q/mc1KP448dLZExECr/wQj
sP9Dh9bMcFRHD96bXu804wVICpsKPj9v7D5j04NfGCYJnRa9B7zUu5HbS5yZJQza
WU/6lL/QgK2ut9pcwwIDAQABo4ICxjCCAsIwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwXAYDVR0gBFUwUzBRBgorBgEEAQkVAQECMEMwQQYIKwYB
BQUHAgEWNWh0dHA6Ly93d3cuY2lzY28uY29tL3NlY3VyaXR5L3BraS9wb2xpY2ll
cy9pbmRleC5odG1sMB0GA1UdDgQWBBQs7Nc+ytYnADiWO5k0x7dhIKIg7zCBuQYD
VR0fBIGxMIGuMC6gLKAqhihodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9P
VENBWDMuY3JsMHygeqB4hnZsZGFwOi8vbGRhcC5pZGVudHJ1c3QuY29tL2NuPURT
VCUyMFJvb3QlMjBDQSUyMFgzLG89RGlnaXRhbCUyMFNpZ25hdHVyZSUyMFRydXN0
JTIwQ28uP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q7YmluYXJ5MIHuBggrBgEF
BQcBAQSB4TCB3jAnBggrBgEFBQcwAYYbaHR0cDovL29jc3B0cy5pZGVudHJ1c3Qu
Y29tMDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1c3QuY29tL3Jvb3Rz
L0RTVFJPT1RDQVgzLmNlcjB2BggrBgEFBQcwAoZqbGRhcDovL2xkYXAuaWRlbnRy
dXN0LmNvbS9jbj1EU1QlMjBSb290JTIwQ0ElMjBYMyxvPURpZ2l0YWwlMjBTaWdu
YXR1cmUlMjBUcnVzdCUyMENvLj9jQUNlcnRpZmljYXRlO2JpbmFyeTBRBgNVHSUE
SjBIBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMFBggrBgEFBQcDBgYIKwYB
BQUHAwcGCCsGAQUFBwMJBgorBgEEAYI3FAIBMB8GA1UdIwQYMBaAFMSnsaR7LHH6
2+FLkHX/xBVghYkQMA0GCSqGSIb3DQEBBQUAA4IBAQBxJm5cX+ycKv/K7yAzFn42
+oQiM8I45792oPjYgoDYUwtc3sZ1/7Di3fglRHwvC1RHhD+h0LV705OSA04DY2FX
NISmsPTcJH3VbOS3VAwV0jLzygtcc5/fbC/hX/PoYWHa6Mk+4T40i5Aw0wjQ8dqi
q0AUdF8ETFTfM4Yk3Ns1AmGAznqU1qdtFZmre12fShW0mu804suOtBwHhjzbBesN
D+3izTYCp0rj//vNHbUy500hGsDGN78LU96nwWXNEOCwHL1RIPXJqY6iq2J6GUpM
syYPde6JtrC9VapvGknb6X3/XyuH8f/ygZf/WFzxMthTkjVawSiisAyK4NVjVREM
-----END CERTIFICATE-----
""")



def get_random_number(size=19, chars=string.digits):
    """
    Generate a random number
        -default size is 19 digits
        -max nonce value that show command can support
    """

    return ''.join(random.choice(chars) for _ in range(size))



def get_random(size=32, chars=string.ascii_uppercase + string.digits):
    """
    Generate a random string
    -default size is 32 characters
    """

    return ''.join(random.choice(chars) for _ in range(size))



def get_data_from_device(address, userid, pass_wd, cmd):
    """
    Generic PnP Get Device Data
    """

    url = ("http://%s/pnp/webui" % address)
    creds = userid + ":" + pass_wd
    auth_string = base64.b64encode(creds)
    headers = {"Authorization":"Basic " + auth_string}
    res = requests.post(url, data=cmd, headers=headers, verify=False)
    return res.text



def create_cert_store():
    """
    Create the Certificate Store to use for Validation
    """

    trust_chain1 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM1)
    trust_chain2 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM2)
    trust_chain3 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM3)
    trust_chain4 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM4)
    trust_chain5 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM5)
    trust_chain6 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM6)
    trust_chain7 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM7)
    trust_chain8 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM8)
    trust_chain9 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM9)
    trust_chain10 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM10)
    trust_chain11 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM11)
    trust_chain12 = crypto.load_certificate(crypto.FILETYPE_PEM, TRUST_CHAIN_PEM12)
    store = crypto.X509Store()
    store.add_cert(trust_chain1)
    store.add_cert(trust_chain2)
    store.add_cert(trust_chain3)
    store.add_cert(trust_chain4)
    store.add_cert(trust_chain5)
    store.add_cert(trust_chain6)
    store.add_cert(trust_chain7)
    store.add_cert(trust_chain8)
    store.add_cert(trust_chain9)
    store.add_cert(trust_chain10)
    store.add_cert(trust_chain11)
    store.add_cert(trust_chain12)
    return store



def get_device_udi_sudi(address, userid, pass_wd):
    """
    get device UDI and SUDI
    """

    # ssh to the device
    login_cmd = "ssh %s@%s" % (userid, address)
    p_p = pexpect.spawn(login_cmd)

    # we should get either a password prompt or prompt asking
    # us to add new key for device to known hosts
    i = p_p.expect(["assword:", "continue connecting", pexpect.TIMEOUT, pexpect.EOF])
    if i == 0:
        # got password prompt, send the password
        p_p.sendline(pass_wd)
    elif i == 1:
        # got new device key prompt, say yes and then look for password prompt and send it
        p_p.sendline("yes")
        p_p.expect("assword:")
        p_p.sendline(pass_wd)
    else:
        # either timed out or some other problem, error out
        print "Failed to login to %s" % address
        return (-1, "UNKNOWN", "UNKNOWN", "UNKNOWN")

    # should get either non priveledged or priveledged prompt
    i = p_p.expect([">", "#"])
    if (i != 0 and i != 1):
        # don't know what happened, error out
        print "Uexpected prompt response on %s" % address
        return (-2, "UNKNOWN", "UNKNOWN", "UNKNOWN")

    # set term length
    p_p.sendline("term len 0")
    p_p.expect([">", "#"])

    # get the SUDI
    p_p.sendline("show crypto pki certificate verbose | i serialNumber=PID:")
    p_p.expect([">", "#"])
    response = p_p.before
    serial_pid = response.split("SN:")
    serial = serial_pid[1].split("\n")
    ret_sudi_serial = serial[0]
    count = len(serial)
    ret_sudi_serial = ret_sudi_serial[:-1]

    # get PID from same output
    pid_line = response.split("PID:")
    pid = pid_line[2].split(" ")
    ret_dev_pid = pid[0]

    # get prompt from same output
    prompt_line = response.split("\n")
    count = len(prompt_line)
    prompt = prompt_line[count-1]

    # now get the UDI
    p_p.sendline("show inventory")
    p_p.expect([prompt])
    response = p_p.before
    outlines = response.split("\n")
    linecount = len(outlines)
    for i in range(linecount):
        if (("Chassis" in outlines[i]) or ("chassis" in outlines[i])):
            ret_udi_line = outlines[i+1]
            break
    ret_udi_line = ret_udi_line[:-1]
    ret_en_udi = ret_udi_line.replace(" ", "")
    return (0, ret_en_udi, ret_sudi_serial, ret_dev_pid)



def get_device_auth_challenge(address, userid, pass_wd, in_en_udi, in_sudi_serial,
                              in_dev_pid, correlator, challenge_phrase):
    """
    Issue Auth Challenge to the Device
    """

    cmd = '''<?xml version="1.0"?>
        <pnp xmlns="urn:cisco:pnp" version="1.0" udi="{dudi}" usr="{pnp_user}" pwd="{pnp_pw}" >
        <request correlator="{corr}" xmlns="urn:cisco:pnp:device-auth">
        <deviceAuth>
          <challenge-request>{message}</challenge-request>
          <encryption-method>RSA,ECDSA</encryption-method>
          <hash-method>SHA256,SHA512</hash-method>
        </deviceAuth>
        </request>
        </pnp>
        '''.format(dudi=in_en_udi, pnp_user=userid, pnp_pw=pass_wd, corr=correlator,
                   message=challenge_phrase)
    resp = get_data_from_device(address, userid, pass_wd, cmd)

    ## initialize data we need
    challenge_rsp = "Unknown"
    dev_sudi = "Unknown"
    enc_method = "Unknown"
    hash_method = "Unknown"
    auth_rc = 0

    ## parse XML response
    elem = ElementTree.fromstring(resp)
    walk_all = elem.getiterator()
    for elt in walk_all:
        if "challenge-response" in elt.tag:
            challenge_rsp = elt.text
        if "sudi-cert" in elt.tag:
            dev_sudi = elt.text
        if "encryption-method" in elt.tag:
            enc_method = elt.text
        if "hashing-method" in elt.tag:
            hash_method = elt.text

    ## make sure we got the data we needed
    if (challenge_rsp is UNKNOWN_STR or dev_sudi is UNKNOWN_STR or
            enc_method is UNKNOWN_STR or hash_method is UNKNOWN_STR):
        print "\tError: Couldn't retrieve device information for authorization"
        return auth_rc

    ## Validate the certificate chain from the device
    dev_sudi_pem = base64.b64decode(dev_sudi)
    store = create_cert_store()
    device_cert = crypto.load_certificate(crypto.FILETYPE_PEM, dev_sudi_pem)
    store_ctx = crypto.X509StoreContext(store, device_cert)
    verify_rsp = store_ctx.verify_certificate()
    if verify_rsp is None:
        print "\tCertificate Validation Passed!"
        auth_rc = auth_rc | 1
    else:
        print "\tCertificate Validation Failed!"

    ## Validate the signature on the challenge is valid
    try:
        verify_rsp = crypto.verify(device_cert, base64.b64decode(challenge_rsp),
                                   challenge_phrase, hash_method)
    except:
        verify_rsp = "Signature Validation Error!"
        print "\t==> ERROR: %s <==" % verify_rsp

    if verify_rsp is None:
        print "\tProof of Possession Validation Passed!"
        auth_rc = auth_rc | 2
    else:
        print "\tProof of Possession Validation Failed: %s" % verify_rsp

    ## Validate the serial number in the Certificate matches the UDI for PnP
    subject = device_cert.get_subject()
    cert_serial = subject.serialNumber.split("SN:")
    if in_sudi_serial == cert_serial[1]:
        print "\tSUDI Serial Number Validation Passed!"
        auth_rc = auth_rc | 4
    else:
        print "\tSUDI Serial Number Validation Failed!"
        print "\t\tExpected: %s, Found: %s" % (in_sudi_serial, cert_serial[1])

    ## Validate the product id in the Certificate matches the PID
    subject = device_cert.get_subject()
    pid_line = subject.serialNumber.split("PID:")
    pid_serial = pid_line[1].split(" ")
    if in_dev_pid == pid_serial[0]:
        print "\tPID Validation Passed!"
        auth_rc = auth_rc | 8
    else:
        print "\tPID Validation Failed!"
        print "\t\tExpected: %s, Found: %s" % (in_dev_pid, pid_serial[0])

    return auth_rc


def get_platform_sudi_status(address, userid, pass_wd, in_en_udi, in_sudi_serial,
                             in_dev_pid, nonce):
    """
    Validate Status of the Platform SUDI using CLI
    """

    # ssh to the device
    login_cmd = "ssh %s@%s" % (userid, address)
    p_p = pexpect.spawn(login_cmd)

    # we should get either a password prompt or prompt asking
    # us to add new key for device to known hosts
    i = p_p.expect(["assword:", "continue connecting", pexpect.TIMEOUT, pexpect.EOF])
    if i == 0:
        # got password prompt, send the password
        p_p.sendline(pass_wd)
    elif i == 1:
        # got new device key prompt, say yes and then look for password prompt and send it
        p_p.sendline("yes")
        p_p.expect("assword:")
        p_p.sendline(pass_wd)
    else:
        # either timed out or some other problem, error out
        print "Failed to login to %s" % address
        return -1

    # should get either non priveledged or priveledged prompt
    i = p_p.expect([">", "#"])
    if i == 0:
        # not in priv mode, enter priv mode
        p_p.sendline("enable")
        p_p.expect("assword:")
        p_p.sendline(in_en_udi)
    elif i == 1:
        # already in priv mode
        p_p.sendline("\n")
    else:
        # don't know what happened, error out
        print "Uexpected prompt response on %s" % address
        return -2

    # should be in priv mode, set term length
    p_p.expect("#")
    p_p.sendline("term len 0")
    p_p.expect("#")

    # issue the show sudi command
    sudi_cmd = 'show platform sudi cert sign nonce ' + nonce
    p_p.sendline(sudi_cmd)
    p_p.expect("#")
    response_output = p_p.before

    # parse the response from the show sudi command
    data_lines = response_output.split("\n")
    line_count = len(data_lines)
    auth_rc = 0
    sig_ver = 0
    signature = ""
    dev_crca_pem = ""
    dev_cmca_pem = ""
    dev_sudi_pem = ""
    cert_num = 1
    for i in range(line_count):
        if "show platform" in data_lines[i]:
            continue
        elif "Signature version:" in data_lines[i]:
            temp = data_lines[i].split(":")
            signature_version = temp[1]
            sig_ver = signature_version.lstrip()
        elif "Signature:" in data_lines[i]:
            signature = data_lines[i+1]
            break
        else:
            if cert_num == 1:
                dev_crca_pem = dev_crca_pem + data_lines[i] + "\n"
            if cert_num == 2:
                dev_cmca_pem = dev_cmca_pem + data_lines[i] + "\n"
            if cert_num == 3:
                dev_sudi_pem = dev_sudi_pem + data_lines[i] + "\n"
            if "END CERTIFICATE" in data_lines[i]:
                cert_num += 1

    ## check data received
    if ((sig_ver == 0) or (signature == "") or (dev_crca_pem == "") or
            (dev_cmca_pem == "") or (dev_sudi_pem == "")):
        print "\tError! Didn't received valid data from device!"
        return -3

    ## Validate the certificate chain from the device
    store = create_cert_store()
    device_crca = crypto.load_certificate(crypto.FILETYPE_PEM, dev_crca_pem)
    device_cmca = crypto.load_certificate(crypto.FILETYPE_PEM, dev_cmca_pem)
    device_sudi = crypto.load_certificate(crypto.FILETYPE_PEM, dev_sudi_pem)

    # verify the root ca certificate
    store_ctx = crypto.X509StoreContext(store, device_crca)
    verify_rsp = store_ctx.verify_certificate()
    if verify_rsp is None:
        print "\tRoot Certificate Validation Passed!"
        # root ca certificate passed, check the manufacturing cert now
        store_ctx = crypto.X509StoreContext(store, device_cmca)
        verify_rsp = store_ctx.verify_certificate()
        if verify_rsp is None:
            print "\tManufacturing Certificate Validation Passed!"
            # manufacturing cert passed, check the SUDI now
            store_ctx = crypto.X509StoreContext(store, device_sudi)
            verify_rsp = store_ctx.verify_certificate()
            if verify_rsp is None:
                print "\tSUDI Certificate Validation Passed!"
                # all 3 certs passed, set the return code bit
                print "\tCertificate Chain Validation Passed!"
                auth_rc = auth_rc | 1
            else:
                print "\tSUDI Certificate Validation Failed!"
                print "\tCertificate Chain Validation Passed!"
        else:
            print "\tManufacturing Certificate Validation Failed!"
            print "\tCertificate Chain Validation Passed!"
    else:
        print "\tRoot Certificate Validation Failed!"
        print "\tCertificate Chain Validation Passed!"

    ## concatenate the nonce and signature version
    nonce_array = format(long(nonce), "X")
    sig_ver_array = format(long(sig_ver), "08X")
    data_to_verify = nonce_array + sig_ver_array

    ## add in the hex representation of the root certificate
    lines = dev_crca_pem.replace(" ", '').split()
    der = binascii.a2b_base64(''.join(lines[1:-1]))
    data_to_verify = data_to_verify + binascii.hexlify(der)

    ## add in the hex representation of the manufacturing cert
    lines = dev_cmca_pem.replace(" ", '').split()
    der = binascii.a2b_base64(''.join(lines[1:-1]))
    data_to_verify = data_to_verify + binascii.hexlify(der)

    ## add in the hex representation of the SUDI cert
    lines = dev_sudi_pem.replace(" ", '').split()
    der = binascii.a2b_base64(''.join(lines[1:-1]))
    data_to_verify = data_to_verify + binascii.hexlify(der)
    data_to_verify = data_to_verify.upper()
    data_bytes = binascii.a2b_hex(data_to_verify)

    # convert the signature to binary
    signature = signature[:-1]
    signature = signature.upper()
    signature_bytes = binascii.a2b_hex(signature)

    # verify the signature over the data
    try:
        verify_rsp = crypto.verify(device_sudi, signature_bytes, data_bytes, 'sha256')
    except:
        verify_rsp = "Signature Validation Error!"
        print "\t==> ERROR: %s <==" % verify_rsp

    if verify_rsp is None:
        print "\tProof of Possession Validation Passed!"
        auth_rc = auth_rc | 2
    else:
        print "\tProof of Possession Validation Failed: %s" % verify_rsp

    ## Validate the serial number in the Certificate matches the SUDI
    subject = device_sudi.get_subject()
    cert_serial = subject.serialNumber.split("SN:")
    if in_sudi_serial == cert_serial[1]:
        print "\tSUDI Serial Number Validation Passed!"
        auth_rc = auth_rc | 4
    else:
        print "\tSUDI Serial Number Validation Failed!"
        print "\t\tExpected: %s, Found: %s" % (in_sudi_serial, cert_serial[1])

    ## Validate the product id in the Certificate matches the PID
    subject = device_sudi.get_subject()
    pid_line = subject.serialNumber.split("PID:")
    pid_serial = pid_line[1].split(" ")
    if in_dev_pid == pid_serial[0]:
        print "\tPID Validation Passed!"
        auth_rc = auth_rc | 8
    else:
        print "\tPID Validation Failed!"
        print "\t\tExpected: %s, Found: %s" % (in_dev_pid, pid_serial[0])


    # issue the show platform integrity command
    sudi_cmd = 'show platform integrity sign nonce ' + nonce
    p_p.sendline(sudi_cmd)
    p_p.expect("#")
    response_output = p_p.before

    # parse the response from the show sudi command
    data_lines = response_output.split("\n")
    line_count = len(data_lines)
    sig_ver = 0
    signature = ""
    pcr0 = ""
    pcr8 = ""
    for i in range(line_count):
        if "Signature version:" in data_lines[i]:
            temp = data_lines[i].split(":")
            signature_version = temp[1]
            sig_ver = signature_version.lstrip()
        elif "Signature:" in data_lines[i]:
            signature = data_lines[i+1]
            break
        elif "PCR0:" in data_lines[i]:
            temp = data_lines[i].split(":")
            pcr0_data = temp[1]
            pcr0 = pcr0_data.lstrip()
            pcr0 = pcr0[:-1]
        elif "PCR8:" in data_lines[i]:
            temp = data_lines[i].split(":")
            pcr8_data = temp[1]
            pcr8 = pcr8_data.lstrip()
            pcr8 = pcr8[:-1]

    ## check data received
    if ((sig_ver == 0) or (signature == "") or (pcr0 == "") or
            (pcr8 == "")):
        print "\tError! Didn't received valid data from device!"
        return -3

    ## concatenate the nonce and signature version
    nonce_array = format(long(nonce), "X")
    sig_ver_array = format(long(sig_ver), "08X")
    data_to_verify = nonce_array + sig_ver_array

    ## add in the PCR0
    data_to_verify = data_to_verify + pcr0

    ## add in the PCR8
    data_to_verify = data_to_verify + pcr8
    data_to_verify = data_to_verify.upper()
    data_bytes = binascii.a2b_hex(data_to_verify)

    # convert the signature to binary
    signature = signature[:-1]
    signature = signature.upper()
    signature_bytes = binascii.a2b_hex(signature)

    # verify the signature over the data
    try:
        verify_rsp = crypto.verify(device_sudi, signature_bytes, data_bytes, 'sha256')
    except:
        verify_rsp = "Boot Integrity Signature Validation Error!"
        print "\t==> ERROR: %s <==" % verify_rsp

    if verify_rsp is None:
        print "\tBoot Integrity Validation Passed!"
        auth_rc = auth_rc | 16
    else:
        print "\tBoot Integrity Validation Failed: %s" % verify_rsp

    return auth_rc


def device_pnp_method(dev_addr, userid, pass_wd, in_en_udi, in_sudi_serial, in_dev_pid):
    """
    PnP Processing
    """

    if ((in_en_udi == "UNKNOWN") or (in_sudi_serial == "UNKNOWN") or (in_dev_pid == "UNKNOWN")):
        print "\tMissing UDI/SUDI/PID for device, retrieving"
        r_c, in_en_udi, in_sudi_serial, in_dev_pid = get_device_udi_sudi(dev_addr, userid, pass_wd)
        if r_c < 0:
            return (0, in_en_udi, in_sudi_serial, in_dev_pid)
        else:
            print "\tUDI(%s) retrieved and stored in dataset" % in_en_udi
            print "\tSUDI(%s) retrieved and stored in dataset" % in_sudi_serial
            print "\tPID(%s) retrieved and stored in dataset" % in_dev_pid

    r_c = get_device_auth_challenge(dev_addr, userid, pass_wd, in_en_udi, in_sudi_serial,
                                    in_dev_pid, get_random(7), get_random())
    return (r_c, in_en_udi, in_sudi_serial, in_dev_pid)



def device_cli_method(dev_addr, userid, pass_wd, in_en_udi, in_sudi_serial, in_dev_pid):
    """
    CLI Processing
    """

    if ((in_sudi_serial == "UNKNOWN") or (in_dev_pid == "UNKNOWN")):
        print "\tMissing SUDI/PID for device, retrieving"
        r_c, temp, in_sudi_serial, in_dev_pid = get_device_udi_sudi(dev_addr, userid, pass_wd)
        if r_c < 0:
            return (0, in_en_udi, in_sudi_serial, in_dev_pid)
        else:
            print "\tSUDI(%s) retrieved and stored in dataset" % in_sudi_serial
            print "\tPID(%s) retrieved and stored in dataset" % in_dev_pid

    r_c = get_platform_sudi_status(dev_addr, userid, pass_wd, in_en_udi, in_sudi_serial,
                                   in_dev_pid, get_random_number())
    return (r_c, in_en_udi, in_sudi_serial, in_dev_pid)



def sanity_check_row(in_row):
    """
    Check input data for proper contents
    """

    ## CSV File Format (CLI): address,method,user,pass,en_pass,sudi_serial,pid
    ## CSV File Format (PNP): address,method,user,pass,udi,sudi_serial,pid

    # check for correct parameter list in the file
    if ((len(in_row) < 4) or (len(in_row) > 7)):
        print "File:%s has invalid row for device(%s)" % (DEVICE_FILE, in_row[0])
        return 0

    # return length of the row
    return len(in_row)



##
# Main processing
##

# parse the input arguments to the command
PARSER = argparse.ArgumentParser()
PARSER.add_argument("a", nargs='?', default="ALL")
ARGS = PARSER.parse_args()
SEARCH_IP = ARGS.a

# read in the device file and either process all
# entries or just the one supplied on the command line
with open(DEVICE_FILE, 'rb') as csvfile:
    ## open a new output file
    with open(OUTPUT_FILE, 'wb') as csv_outfile:
        CSV_OUT = csv.writer(csv_outfile, delimiter=',', quotechar='"')

        ## read the device file contents
        DEVFILE = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in DEVFILE:
            # check for device address passed in on command line
            if SEARCH_IP != "ALL":
                if SEARCH_IP != row[0]:
                    # not the device we want to verify, skip it
                    CSV_OUT.writerow(row)
                    continue

            rc = sanity_check_row(row)
            if rc == 0:
                # row we wanted to process was invalid, write out and continue
                CSV_OUT.writerow(row)
                continue

            # store required parameters
            dev_address = row[0]
            method = row[1]
            user = row[2]
            passwd = row[3]
            en_udi = "UNKNOWN"
            sudi_serial = "UNKNOWN"
            dev_pid = "UNKNOWN"

            # partial 5 tuples
            if rc == 5:
                en_udi = row[4]

            # partial 6 tuples
            elif rc == 6:
                en_udi = row[4]
                sudi_serial = row[5]

            # Full parameter list
            elif rc == 7:
                en_udi = row[4]
                sudi_serial = row[5]
                dev_pid = row[6]

            # shouldn't get here
            else:
                # row we wanted to process is fubar somehow, skip it
                CSV_OUT.writerow(row)
                continue

            rc = 0
            print "Verifying %s using %s:" % (dev_address, method)
            if method == "PNP":
                rc, en_udi, sudi_serial, dev_pid = device_pnp_method(dev_address, user, passwd,
                                                                     en_udi, sudi_serial, dev_pid)
            elif method == "CLI":
                rc, en_udi, sudi_serial, dev_pid = device_cli_method(dev_address, user, passwd,
                                                                     en_udi, sudi_serial, dev_pid)
            else:
                print "\tERROR: Unknown processing method %s" % method

            if rc == 31:
                print "Result: Passed(%d)\n\n" %  rc
            else:
                print "Result: Failed(%d)\n\n" %  rc

            # write out the row to the output file
            if (en_udi == "UNKNOWN" or sudi_serial == "UNKNOWN" or dev_pid == "UNKNOWN"):
                CSV_OUT.writerow(row)
            else:
                CSV_OUT.writerow([dev_address, method, user, passwd, en_udi, sudi_serial, dev_pid])

# update the data files
print "Updating the %s file to contain latest data" % DEVICE_FILE
os.rename(DEVICE_FILE, OLD_DEVICE_FILE)
os.rename(OUTPUT_FILE, DEVICE_FILE)
print "Finished Processing"
