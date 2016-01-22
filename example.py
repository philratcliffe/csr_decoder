from csr import CSR


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


# Create a CSR object from a PEM encoded CSR
valid_csr = CSR.from_pem(VALID_CSR)

# Print some attributes
print valid_csr.cn
print valid_csr

raw_input("hit any key for next decode")

# Read the binary encoded CSR from a file
with open("csr.der", "rb") as f:
    der_csr = f.read()

# Create a CSR object from a binary encoded CSR
csr = CSR.from_binary(der_csr)

# Print some attributes
print valid_csr.cn
print valid_csr.openssl_text

