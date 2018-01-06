import unittest

from ameshthing.chacha20 import ChaChaBox


class ChaChaBoxTests(unittest.TestCase):

    def setUp(self):

        TEST_KEY = (b'\x00' * 31) + b'\x55'
        # b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x55"
        self.TEST_NONCE = b"\x00\x01\x02\x03\x04\x05\x06\xee"

        self.PLAINTEXT = b'Hello there,\x00 ChaCha! Go dance with those moduli!'
        self.EXPECTED_CIPHER = b'\x00\x01\x02\x03\x04\x05\x06\xeeb\xde\x98a&\x18\xc6&M(\x10\xf8\x9dBn\xa5\xbb\xe3\xd7bScX\xdct\xb1o\x92\x83I\xd3E\x81=9\xe0$6\xdbM\x7f\x94\x9a\x1e\xbb\xa0x\xe2@'

        self.box = ChaChaBox(TEST_KEY)

    def test_encrypt(self):
        e = self.box.encrypt(self.PLAINTEXT, self.TEST_NONCE)

        self.assertEqual(e, self.EXPECTED_CIPHER)

    def test_decrypt(self):
        d = self.box.decrypt(self.EXPECTED_CIPHER)

        self.assertEqual(d, self.PLAINTEXT)


    def test_bad_secret_key(self):
        self.assertRaises(ValueError, ChaChaBox, (b'\x31' * 31))
        self.assertRaises(ValueError, ChaChaBox, (b'\x33' * 33))

        ccb = ChaChaBox('not bytes not bytes not bytes \x01\x02')
        self.assertRaises(TypeError, ccb.encrypt, (b'hello', b'12345678'))

        self.assertRaises(TypeError, self.box.encrypt, (b'bytes nonce is not', '12345678'))
        self.assertRaises(TypeError, self.box.encrypt, ('this not bytes, nonce is', b'12345678'))
