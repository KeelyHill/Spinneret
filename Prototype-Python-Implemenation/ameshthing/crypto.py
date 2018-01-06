# Where the cryto stuffs will go (abstracted for simple, specific use)

# Dual key (two key pairs one signing one encytion exchange)

# from .chacha20 import foobar


import nacl.utils
from nacl.hash import sha256

from nacl.signing import SigningKey, VerifyKey

from nacl.public import PrivateKey, Box, PublicKey

from nacl.encoding import RawEncoder

from nacl.encoding import Base64Encoder as nacl_Base64Encoder

from nacl.secret import SecretBox, EncryptedMessage

from .chacha20 import ChaChaBox

from .util import base64_encode, base64_decode



class Crypto():
    """"Crypto handels the cryptography of a Node
    from network signing and encryption (and decrypting and verifying),
    to payload encyption and decrpytion. Also includes addressing.

    Note: Should only be used as variable of a Node

    When initallized no keys are set, they must either be generated or loaded.
    >>> c = Crypto()
    >>> c.create_dual_keys()  # creats a 'new' node

    >>> save = c.get_save_key_dict()  # save and
    >>> c.load_keys_from_save_dict(save)   #  load the keys


    Useful functions:

    >>> encrypt_to_public_key(to_key)

    >>> sign_and_encrypt_with_network_key(data)
    >>> decrypt_from_network_and_verify(data)

    >>> encrypt_symmetrically(payload, key)
    >>> decrypt_symmetrically(payload, key)


    >>> c.public_address  # derived from verifiying key

    """

    def __init__(self):

        # Used only to sign
        self.signing_key = None  # 'private'
        # public verify via self.signing_key.verify_key

        # For the key exchange for individual-to-individual encryption
        self.private_key = None
        # public via self.private_key.public_key

        # generated from `public_address` property getter, different from public key
        self.__public_address = None


        self.network_secret_box = None

        #self.signing_key = nacl.signing.SigningKey.generate()
        # self.verify_key = self.signing_key.verify_key

    @property # no setter
    def public_address(self):
        if self.__public_address == None: # { generate if nessisary
            first = sha256(self.signing_key.verify_key.encode(), RawEncoder)
            double_sha = sha256(first, RawEncoder)

            # base64 encode, the take first 7 chars aka url and filename safe
            self.__public_address = base64_encode(double_sha, b'-_')[:7]
        # }

        return self.__public_address



    def get_save_key_dict(self):
        return {
            'net': base64_encode(self.network_secret_box.secret_key),
            'sign': self.signing_key.encode(encoder=nacl_Base64Encoder),
            'priv': self.private_key.encode(encoder=nacl_Base64Encoder),
            'addr': self.public_address
        }

    def load_keys_from_save_dict(self, save:dict):

        self.network_secret_box = ChaChaBox(base64_decode(save['net']))

        self.signing_key = SigningKey(save['sign'], encoder=nacl_Base64Encoder)

        self.private_key = PrivateKey(save['priv'], encoder=nacl_Base64Encoder)

        self.__public_address = save['addr']


    def create_dual_keys(self):
        """Call only when fresh node. These keys _are_ the node."""

        # Used only to sign
        self.signing_key = SigningKey.generate()

        # For the key exchange for individual-to-individual encryption
        self.private_key = PrivateKey.generate()


    def set_network_key(self, key:bytes):
        self.network_secret_box = ChaChaBox(key)


    def encrypt_to_public_key(self, plaindata:bytes, key:bytes):

        box = Box(self.private_key, PublicKey(key))

        nonce = nacl.utils.random(Box.NONCE_SIZE)

        encrypted_message = box.encrypt(plaindata, nonce)

        return encrypted_message


    def decrypt_from_public_key(self, cipher_data:bytes, key:bytes):

        box = Box(self.private_key, PublicKey(key))

        return box.decrypt(cipher_data)



    def sign_and_encrypt_with_network_key(self, message:bytes):
        """Returns the signed then encypted message (broadcast).
        Signed with signing key, encrypted with symettric network key.
        """

        signed = self.signing_key.sign(message)

        # *MUST* only be used once, but it is not considered
        #   secret and can be transmitted or stored alongside the ciphertext. A
        #   good source of nonce is just 24 random bytes.
        nonce = nacl.utils.random(ChaChaBox.NONCE_SIZE)

        encrypted = self.network_secret_box.encrypt(signed, nonce)

        return encrypted


    def decrypt_from_network(self, encrypted):
        return self.network_secret_box.decrypt(encrypted)

    def verify_signed_bytes(self, signed:bytes, verify_key_raw:bytes):
        verify_key = VerifyKey(verify_key_raw) # convert to NaCl object

        return verify_key.verify(signed)


    @staticmethod
    def encrypt_symmetrically(plain_data:bytes, key:bytes):
        """ChaCha20 encrypts plain data with key."""

        nonce = nacl.utils.random(ChaChaBox.NONCE_SIZE)

        box = ChaChaBox(key)

        return box.encrypt(plain_data, nonce)

    @staticmethod
    def decrypt_symmetrically(cipher_data:bytes, key:bytes):
        """ChaCha20 decrypts cipher data using passed key"""

        box = ChaChaBox(key)

        return box.decrypt(cipher_data)
