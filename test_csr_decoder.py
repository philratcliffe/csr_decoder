import unittest
import os
import logging
from csr import CSR

class TestCsrDecoding(unittest.TestCase):
    def setUp(self):
        self.ec_csr = get_csr_from_file('ec-csr.pem')
        self.dsa_csr = get_csr_from_file('dsa-csr.pem')

    def test_ec_key_alg(self):
        self.assertEqual(self.ec_csr.get_pubkey_alg(), 'ECDSA')
        self.assertEqual(self.ec_csr.keysize, 521)

    def test_dsa_key_alg(self):
        self.assertEqual(self.dsa_csr.get_pubkey_alg(), 'DSA')
        self.assertEqual(self.dsa_csr.keysize, 1024)

def get_csr_from_file(filename):
    dir_name = os.path.dirname(os.path.realpath(__file__))
    fname = filename
    fname_full = os.path.join(dir_name, fname)
    with open(fname_full, 'r') as f:
        pem = f.read()
    csr = CSR.from_pem(pem)
    return csr

if __name__ == '__main__':
    log_level = logging.ERROR
    logging.basicConfig(format="%(levelname)s %(asctime)s %(funcName)s %(lineno)s %(message)s", level=log_level)
    unittest.main()
