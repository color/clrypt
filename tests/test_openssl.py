import os.path
import unittest

import clrypt.openssl


TEST_CERT_DIR = os.path.join(os.path.dirname(__file__), 'test-cert')


class TestBignumToMPI(unittest.TestCase):
    """Make sure we're encoding integers correctly."""

    def test_exponent(self):
        self.assertEqual(
            clrypt.openssl.bignum_to_mpi(65537),
            b'\x00\x00\x00\x03\x01\x00\x01')

    def test_modulus(self):
        self.assertEqual(
            clrypt.openssl.bignum_to_mpi(
                17652187434302119818626903597973364646688501428151181083346396650190495499971143555821153235865918471667488379960690165155890225429359619542780951438912782907420720337860016081609304413559138090809578303571230455363722891195091112107003860558073312270213669052061287420596945410842819944331551665414956709934244337764287956982989490636986364084315970710464920930036478862933506058288047831177960977170956029647528492070455408969834953275116251472162035375269818449753491792832735260819579628653112578006009233208029743042292911927382613736571054059145327226830704584124567079108161933244408783987994310178893677777563
            ),
            b'\x00\x00\x01\x01\x00\x8b\xd5\x0e\xf7s\xde\xce\xcayg\xe5s\xaf'
            b'\xa5\\\x95\xd9\xbd\xb3\xff4\xa9\x98T\xe6^\x91\xcc\xb9X\xda*'
            b'\xf3W@\xed\x8b\xd7E\rB\xa7\x17l\x83_s\x8479\xa2\x92}SL\x007g'
            b'\x829\xfdz\x1bwf\x060}\xd1\xaagXF\xf1\x12n\x96z\xba\xa3\xd9'
            b'\xb1\x91\x98\x99\xf4.\xbfo\xd1\x13\xb8\x97p^*\x16\x0bi~\xd5'
            b'\x10\x07\xa7\x7f\x86D\x9a\xf3]0YZ4\xea\xe9\x17\xe1\x86\x96'
            b'\xad\xe9;\xcf\xd3T+\x91U#K.\xdb\xcc\x06\x90e]\x88\x0e[hs\xde'
            b'\xbbm\x16\xc9\x19@\xd9{FI\x04\xe7\xf6\xd5\xcb\xff\xe7&\xce'
            b'\xaa\x0e\x88{\xc7\xfa\xe6\x94d\x1d\xf9\x00\x18\xa2[\xeaf\xf1'
            b'\xea\xe7\xc2ZG\x99\xfc\xe8\xb9|\xc7\xa4r\x06\x7f\x1e\tA\xaa'
            b'\x1a\xe6\xe0\x86\x85\x11\xf0q?\xdc\xa0c\xbey\x05[u\xe5}>\xf5'
            b'\xfc\x85\xaa\xff\x93v\xf7\xdf\xc6\xffv\xcei47\x03\xb1\xd0vR'
            b'\x90\x16\xf5\x1a\xad\x1eH\x9dRW(\xea\xa4\xd2\x9b',
        )


class TestOpenSSLKeypair(unittest.TestCase):

    def setUp(self):
        self.keypair = clrypt.openssl.OpenSSLKeypair(
            os.path.join(TEST_CERT_DIR, 'test.crt'),
            os.path.join(TEST_CERT_DIR, 'test.dem'))

    def test_key_id(self):
        """A regression test: key IDs should never change."""
        self.assertEqual(
            self.keypair.get_key_id(),
            "05f8ef9229fe21844aacfe2ec6e63e2b")

    def test_encryption_cycle(self):
        """A smoke test: check that decrypt(encrypt(text)) == text."""
        message = b"Some message"
        encrypted = self.keypair.encrypt(message)
        self.assertNotEqual(encrypted, message)
        decrypted = self.keypair.decrypt(encrypted)
        self.assertEqual(decrypted, message)
