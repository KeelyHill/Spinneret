"""A python interface for using ChaCha20 for symmetric encryption with C++ at the core.

Basic Usage:
>>> box = ChaChaBox(secret_key_32_byte)
>>> ciphertext = box.encrypt(b'Do the salsa with a shake!', nonce_8_byte)
>>> plaintext = box.decrpyt(ciphertext, nonce_8_byte)

"""


from ._chacha20 import crypt as chacha20_crypt # import from C

class ChaChaBox():
    """Python binding to C XOR ChaCha20

    # IDEA i'd like to support 12 byte (96-bit) nonces

    Note: This is only symmetric encryption, no extra MAC (like Poly1305)
    """

    KEY_SIZE = 32
    NONCE_SIZE = 8

    def __init__(self, secret_key):
        """Initializes ChaChaBox with secret key.
        :secret_key: symmetric key bytes object with size `ChaChaBox.KEY_SIZE`
        """

        if len(secret_key) != self.KEY_SIZE:
            raise ValueError('Secret key must be %i bytes.' % self.KEY_SIZE)

        self.secret_key = secret_key

    def encrypt(self, plaintext, nonce):
        """Encrypts plaintext with the box's symmetric secret key.
        Prepends nonce to front of ciphertext. [nonce][actual ciphertext]

        :plaintext: the plaintext bytes-like object
        :nonce: MUST be random of size `ChaChaBox.NONCE_SIZE`

        """

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError('Nonce must be %i bytes.' % self.NONCE_SIZE)


        # FIXME when passed to C, it is by ref, therefore the plain text python 'pointer'
        # gets manipualated into the cipher text (as it should it C), but also
        # affects the python variable being passed
        ciphertext = chacha20_crypt(plaintext, nonce, self.secret_key)

        return nonce + ciphertext

    def decrypt(self, ciphertext):
        """Decrypts ciphertext using the symmetric key and the prepended nonce.

        :ciphertext: [nonce][actual ciphertext]
        """

        nonce = ciphertext[:self.NONCE_SIZE]
        ciphertext_only = ciphertext[self.NONCE_SIZE:]

        return chacha20_crypt(ciphertext_only, nonce, self.secret_key)

    def __repr__(self):
        return "<ChaChaBox object>"
