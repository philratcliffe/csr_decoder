import unittest
import os
import logging
from csr import CSR


class TestCsrDecoding(unittest.TestCase):
    def setUp(self):
        self.ec_csr = get_csr_from_pem_file('ec-csr.pem')
        self.dsa_csr = get_csr_from_pem_file('dsa-csr.pem')
        self.rsa_csr = get_csr_from_pem_file('rsa-csr.pem')

    def test_ec_key_alg(self):
        self.assertEqual(self.ec_csr.get_pubkey_alg(), 'ECDSA')

    def test_ec_key_len(self):
        self.assertEqual(self.ec_csr.keysize, 521)

    def test_ec_openssl_text(self):
        text = self.ec_csr.openssl_text
        self.assertRegex(text, b'acme')

    def test_ec_cn(self):
        self.assertEqual(self.ec_csr.cn, b'www.acme.com')

    def test_dsa_key_alg(self):
        self.assertEqual(self.dsa_csr.get_pubkey_alg(), 'DSA')

    def test_dsa_key_len(self):
        self.assertEqual(self.dsa_csr.keysize, 1024)

    def test_dsa_openssl_text(self):
        text = self.dsa_csr.openssl_text
        self.assertRegex(text, b'test-dsa')

    def test_dsa_cn(self):
        self.assertEqual(self.dsa_csr.cn, b'test-dsa')

    def test_rsa_key_alg(self):
        self.assertEqual(self.rsa_csr.get_pubkey_alg(), 'RSA')

    def test_rsa_openssl_text(self):
        text = self.rsa_csr.openssl_text
        self.assertRegex(text, b'rkc.com')

    def test_rsa_key_len(self):
        self.assertEqual(self.rsa_csr.keysize, 4096)

    def test_rsa_cn(self):
        self.assertEqual(self.rsa_csr.cn, b'rkc.com')


def get_csr_from_pem_file(filename):
    dir_name = os.path.dirname(os.path.realpath(__file__))
    fname = filename
    fname_full = os.path.join(dir_name, fname)
    with open(fname_full, 'r') as f:
        pem = f.read()
    csr = CSR.from_pem(pem)
    return csr

if __name__ == '__main__':
    log_level = logging.ERROR
    logging.basicConfig(
        format="%(levelname)s %(asctime)s %(funcName)s %(lineno)s %(message)s",
        level=log_level)
    unittest.main()
