import base64

def base64_decode(data):
    """Decode base64, padding being optional.

    data: Base64 data as a byte string

    returns the decoded byte string.
    """
    missing_padding = 4 - len(data) % 4
    if missing_padding != 4:
        data += b'='* missing_padding


    return base64.b64decode(data)

def base64_encode(btye_str, altchars=None):
    return base64.b64encode(btye_str, altchars)


def safe_base64_decode(data):
    try:
        return base64_decode(data)
    except:
        return None
