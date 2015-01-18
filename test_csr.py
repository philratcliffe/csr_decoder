import os

import unittest
from csr import CSR


class TestMixin(object):

    def test_subject(self):
        expected_result = [
            ('C', 'gb'), ('ST', 'staffs'), ('L', 'stoke'),
            ('O', 'CSR Decoders'), ('CN', 'www.decodecsr.co.uk'),
        ]

        self.assertItemsEqual(
            self.csr.subject,
            expected_result,
            "subject does not equal expected subject")
    def test_cn(self):
        self.assertEqual(
            self.csr.cn,
            "www.decodecsr.co.uk",
            "expected cn value not found")

    def test_get_openssl_text_cn(self):
        text = self.csr.get_openssl_text()
        self.assertRegexpMatches(
            text,
            "www.decodecsr.co.uk",
            "expected cn pattern not found")


class TestValidCsrPEM(TestMixin, unittest.TestCase):
    def setUp(self):
        self.csr = CSR.from_pem(VALID_CSR)

class TestValidCsrDER(TestMixin, unittest.TestCase):
    def setUp(self):
        binary_csr = get_binary_data_from_file("csr.der")
        self.csr = CSR.from_binary(binary_csr)

def get_binary_data_from_file(filename):
    """
    Reads and returns the binary data from the provided file.
    It assumes the file will be in the same directory as this file
    """

    dir_name = os.path.dirname(os.path.realpath(__file__))
    filename_full = os.path.join(dir_name, filename)
    with open(filename_full, mode='rb') as file:
            file_content = file.read()

    return file_content




VALID_CSR = """
-----BEGIN CERTIFICATE REQUEST-----
MIIBozCCAQwCAQAwYzELMAkGA1UEBhMCZ2IxDzANBgNVBAgTBnN0YWZmczEOMAwG
A1UEBxMFc3Rva2UxFTATBgNVBAoTDENTUiBEZWNvZGVyczEcMBoGA1UEAxMTd3d3
LmRlY29kZWNzci5jby51azCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzrUU
2GDhmYUY7qJ/UgUanDOF7ou9PG9xyng1du/Cbj1T6Sq48GnChgfAy9p/VwVOW4RA
393vMM6ewfUx18S9Um3V0LZ4m4a2Qyn5ZQAO2lwVmtKFDkFjnn6NndyC1xtB9kQg
TU4mne4cvvHuxxDTssdjiu0qFRFwqA5NST32r4ECAwEAAaAAMA0GCSqGSIb3DQEB
BQUAA4GBADaragMxUdVEpATqDSGj2twASbCloT5OdeSjE2/dha+6nSTe8mN/7ALD
E2gtYXyfY1xebfxbMzddKkl/OTRyBnBS1VemuG5XzUkU9b1dCoV6dcxGVb0K0Z9D
4d5P9aqq//WHGKIwDsfut4gAAjrOshLlw6b4eFLacuRLRVuv+qBE
-----END CERTIFICATE REQUEST-----
"""
