import OpenSSL


class CSR:
    """Decodes CSRs"""

    def __init__(self, x509):
        self.x509 = x509

    @classmethod
    def from_pem(cls, pem_csr):
        """Initialise CSR from a PEM encoded CSR"""
        x509 = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, pem_csr)
        return cls(x509)

    @classmethod
    def from_binary(cls, binary_csr):
        """Initialise CSR from a binary CSR"""
        """TODO: implement me"""
        raise NotImplementedError

    @property
    def cn(self):
        """Returns the CN from the subject if present"""
        c = None
        for rdn in self.subject:
            if rdn[0] == "CN":
                c = rdn[1]
        return c

    @property
    def subject(self):
        """Returns the subject of the CSR"""
        return self.x509.get_subject().get_components()

    def get_openssl_text(self):
        """Returns the OpenSSL output for the CSR"""
        text = OpenSSL.crypto.dump_certificate_request(
            OpenSSL.crypto.FILETYPE_TEXT,
            self.x509)
        return text
