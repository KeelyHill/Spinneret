# deals with the authority/user keys

class AuthCrypto:

	def __init__(self, signing_key=None, private_key=None):

		if (signing_key and not private_key) or (private_key and not signing_key):
			raise Exception('If instantiating with keys, both must be provided.')
			return

		
