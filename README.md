# VerifyBIV

**Description**:

Some Cisco products take measurements of the code executed as they boot up.
These measurements are recorded in a hardware Trust Anchor Module, and can be
subsequently retrieved in a cryptographically-signed report. This script
analyzes the Boot Integrity report to validate its authenticity and to confirm
that the report data has not been tampered.

The script takes the signed output from the IOS CLI commands 

``show platform integrity signed nonce <int>`` 

and

``show platform sudi certificate signed nonce <int>``

from supported network devices and verifies the integrity of the respective
command output using the device specific SUDI certificate from the latter
command.

Supported platforms and releases (subject to change):
```
|  Cisco Platform        | Minimum Software  |  Minimum ROMMON/Bootloader |
|  --------------------- | ----------------- | -------------------------- |
|  ISR44xx, ISR443xx     | 16.2.1            | 16.2(1r)                   |
|  ISR 4221              | 16.4.1            | N/A (bundled in software)  |
|  ASR1001-hx, ASR1001-x | 16.3.2            | 16.3(2r)                   |
|  ASR1002-hx, RP3       | 16.3.2            | 16.3(2r)                   |
|  Select Catalyst 3650  | 16.3.2            | 4.26                       |
|  Select Catalyst 3850  | 16.3.2            | 4.28                       |
```
 
The purpose of this script is for localized verification of a small number of
devices in lieu of utilizing a network management system to perform the same
verification across a large number of network devices.

This script is written in Python 2.7. It is intended to run independently of
other tools.

**Status**:

Initial release.

## Dependencies

__VerifyBIV__ requires two open source packages:

### __pycrypto__ <http://www.pycrypto.org/> ###
Use [pip](http://pip-installer.org):

    pip install pycrypto

_NOTE:_ On Windows, change pycrypto's folder name from crypto to Crypto.

### __docopt__ <http://docopt.org/> ###
Use [pip](http://pip-installer.org):

    pip install docopt

## Installation

__VerifyBIV__ is ready to run after download. Mark the ``VerifyBIV.py`` file as
executable to run it in a Linux environment. Also if necessary modify the
``#!`` line at the beginning of this file to the path of a python2.7 interpreter.

## Usage

```
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
```

__NOTE:__ Minimum 100 character width console recommended

Example ``SUDI_FILE`` provided: sudi\_example.txt

Example ``SPI_FILE`` provided: spi\_example.txt

## How to test the software

Use the included sample files to verify operation.

__Example CLI operation:__

```
$ VerifyBIV.py -s sudi_example.txt -i spi_example.txt

Gathering identity info...

   Nonce:               123
   Certificates Found:  3
   Signature Version:   1
   Signature:
        7BADC9C17EE606E584F6B3B9C957DBC98EBDBBE9BEFB1A9FCD8B6E084C2C41C5
        6F3B29E73FF9459BF5169DF9628F72E58C06FF44D2F3BEEB66FA40F09498FFBA
        B299739537C360D5D11ADB273DD275679D194FC0B31A9E169C6C99BD89A2833B
        FF7A41CF65A2572C6BFC120349C8A25C5A519AF14A3BAC0ABAF3FB477C01ABB2
        01FE342234B3E18EDE478A2D278B1AE218CE0AC191A09D592913F76A915E4D37
        68AD58E5E8179F8ADA7F4C9DC9019E65E4AD918670462D38FDAF5541543FF2DF
        89A2E33FB80FD19AF4BFB0FF1F5B1DA3012CB0F3E20D73D96474782346BAD7A4
        DE13114BE3AE6C5E60E76B1B99D59E7E947276A7BA2AEB6CD785C394EF44B8EA

Verifying platform identity signature...

   Platform identity verification:              SUCCESSFUL 


Gathering integrity info...

   Nonce:       123
   PCR0:        36E1A27DC9115FD08165710F6715AB345B9337A2B329E303A4C869F72EC81C33
   PCR8:        44F9646B04860009FC45105F816FE01DC39C7DB29401A158B13FECB26749F470
   Signature Version:   1
   Signature:
        18992E8DC490E8A932F152FD981A8AF1F95B69C8A1C531F5E14EB52CBDD720B8
        34E6F1B64AB38FEB3B2FB5E20407B16699E3E4E2F1E9BF7160B3E92A95E2F375
        9CFE02101C9EE8D508CF178D10FA2121BEC78349BD9D58EE0CBC72FE3F7A9359
        9828A9DDDE3B0C7F3B1DDB9982883D13729B92BA312EF6F107DF7D40F3BE239A
        C203DF64E17AC80ADE62A3D33301D57EE03ED83067BEBEA44B82E9CF5F5587B2
        DEE28C07898E5F3110816E2281B3FE8ACBEA2BEEB718F2F5CE0A36802F456CDF
        D905275FBC89F2A5EE9CC849E825EE8D799B690EACC1BA7A631B8266FC237CE4
        8BE2809C2FC0D1727DB73D8D68956180822440F74C7F6FBAB29BF45FA820FE5C

Verifying platform integrity signature...

   Platform integrity verification:     SUCCESSFUL 

```
## Known issues

None.

## Getting help

Mailing list for questions about this script: verifybiv-tool AT ciscoDOTcom.

Cisco Community forum coming soon.

## Getting involved

This script is provided as a reference for how to perform verification of
signed BIV command output. The intent is for others to explore the BIV feature
on supported network devices and adapt this verification method to their needs.

## Open source licensing info
[LICENSE](LICENSE)

## Credits and References

[Information about Boot Integrity Visibility](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/configuration/xe-16/fundamentals-xe-16-book/bt-it-vis.html)

[Trust Center - Cisco](https://trust.cisco.com)
