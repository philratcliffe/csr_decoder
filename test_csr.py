import unittest
from csr import CSR


class TestCSR(unittest.TestCase):
    def setUp(self):
        self.valid_csr = CSR.from_pem(VALID_CSR)

    def test_cn(self):
        self.assertEqual(
            self.valid_csr.cn,
            "www.decodecsr.co.uk",
            "expected cn value not found")

    def test_get_openssl_text_cn(self):
        text = self.valid_csr.get_openssl_text()
        print text
        self.assertRegexpMatches(
            text,
            "www.decodecsr.co.uk",
            "expected cn pattern not found")


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
