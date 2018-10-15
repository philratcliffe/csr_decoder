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


# Create a CSR object from the PEM encoded CSR above.
csr = CSR.from_pem(VALID_CSR)

# Print out the CN from the DN.
print(csr.cn.decode('utf-8'))

# Print out the OpenSSL text representation of the CSR
print(csr.openssl_text.decode('utf-8'))

# Read a binary encoded CSR into memory.
with open("csr.der", "rb") as f:
    der_csr = f.read()

# Create a CSR object from a binary encoded CSR
csr = CSR.from_binary(der_csr)

# Print out the CN from the DN.
print(csr.cn.decode('utf-8'))

# Print out the OpenSSL text representation of the CSR
print(csr.openssl_text.decode('utf-8'))

# Print the type of the variable containing the CSR subject
print("Type of csr.subject is: " + str(type(csr.subject)))
