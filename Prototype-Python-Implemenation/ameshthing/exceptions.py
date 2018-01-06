
class NotToMeException(Exception):
    """Raise when the broadcast is not to the node in any way."""
    pass


class NotInSecureGroupException(Exception):
    """Raised if a node attempts to encrypt a payload for a secure group
    and can't becuase it is not a part of the group."""
    pass

class UnknownNodeException(Exception):
    """Raised when a payload is to be encypted, but the public key of the recipient is unknown."""
    pass



class ArgumentValidationError(Exception):
    """Raised when requested arguments are invalid."""
    pass

class ExceptionWithResponse(Exception):
    """An Exception occured and a RESP broadcast is to be sent back."""

    def __init__(self, resp_code, message, back_to=None):

        super().__init__(message)

        self.message = message

        self.resp_code = resp_code
        self.back_to = back_to

class TransmissionError(Exception):
    """Raised the physical transmission fails for some reason."""
    pass



class EncodingError(Exception):
    """Error when encoding an object"""
    pass

class DecodingError(Exception):
    """Error when decoding an object"""

    def __init__(self, message, char:int=None):

        if char != None:
            char += 1  # index to position
            message = '%s at pos %i' % (message, char)

        super().__init__(message)
