# -*- coding: utf-8 -*-
"""
Module for encoding and decoding the $name-o-encoding encoding.

Spec:
    string = s[len]:[val]
    int = i[val];
    float = f[val];
    bool = T or F
    null = n
    list = l[items];
    dict = d[key][value][key][value]...;

    Property = p[name]|[type repr]|[value]|[meta];
    Action = ^[action_name]([$action-parameter;]...)[return_type repr];
        Action Parameter = $[name]|[type]|[meta];
    Node = node<[p...;]...|[^action(...);]...|node-info-dict>

"""

# from .node import BaseNode
from .constructs import BaseNode, Property, Action, ActionParameter
from .types import types

from .exceptions import EncodingError, DecodingError


def utf8bytes(obj):
    """Takes an object and converts it to a byte string"""
    return bytes(str(obj), 'utf-8')

def encode(obj, force_type=None):
    """Preliminary function used by encode().
    Encodes python objects to a python string.
    Byte strings (i.e. b'...') and unicode are encoded with
    the correct length as utf-8 even though as a pre utf-8
    python string len == 1.

    ** Warning: Never use this outside of encoding.encode()

    Note: string lengths need to be corrected by
    encoding return as utf-8 outside this function.
    """

    if obj == None:
        return b'\x00'

    if type(obj) is bool:
        return b'T' if obj else b'F'

    if type(obj) is int:
        if force_type == 'I':
            return b'I' + utf8bytes(obj) + b';'

        return b'i' + utf8bytes(obj) + b';'

    if type(obj) is float:
        return b'f' + utf8bytes(obj) + b';'

    if isinstance(obj, str):
        return b's' + utf8bytes(len(obj.encode('utf-8'))) + b':' + obj.encode('utf-8')

    if isinstance(obj, bytes): # use z for bytes or base64 data

        return b'z' + utf8bytes(len(obj)) + b':' + obj

    if isinstance(obj, list):
        res = b'l'
        for elem in obj:
            res += encode(elem)
        return res + b';'

    if isinstance(obj, dict):
        res = b'd'
        for key in sorted(obj.keys()):
            res += encode(key) + encode(obj[key])
        return res + b';'

    ## Special Types

    if type(obj) is Property:
        return b'p%s|%s|%s|%s;' % (
            utf8bytes(obj.name), utf8bytes(obj._type.repr),
            encode(obj.value), encode(obj.meta))

    if type(obj) is Action:
        encoded_params = []
        if len(obj.action_parameters) > 0:
            encoded_params = [encode(param) for param in obj.action_parameters]

        return b'^%s(%s)%s;' % (
                utf8bytes(obj.name),
                b''.join(encoded_params), # combine one after the other
                utf8bytes(obj.return_type.repr)
                )

    if type(obj) is ActionParameter:
        return b'$%s|%s|%s;' % (utf8bytes(obj.name), utf8bytes(obj._type.repr), encode(obj.meta))


    if isinstance(obj, BaseNode): # isinstance used so subclasses are included.
        encoded_actions = [encode(a) for a in obj.actions.values()]
        encoded_properties = [encode(p) for p in obj.properties.values()]

        return b'node<%s|%s|%s>' % (
                b''.join(encoded_properties),
                b''.join(encoded_actions),
                encode(obj.node_info)
        )


    raise EncodingError('Unknown object type when encoding: %s' %repr(obj))







def decode(data:bytes):
    """Decodes ('loads') a byte string of $name encoding into a python object.

    Note: bytestrings are utf-8 encoded, thus are decoded to python strings
    on decoding. Data marked as binnary (with 'z') is infered as base 64 data
    and represented as a bytearray.
    """

    if type(data) != bytes:
        raise TypeError('a bytes-like object is required, not \'%s\'' % type(data).__name__)

    # used to make sure decoding does not go deep enough to cause vulnerability
    max_depth = 200
    cur_depth = 0

    def decode_next(start):
        nonlocal cur_depth

        if len(data) <= start:
            raise DecodingError('Unexpected end of data', start)

        # print('decode depth =',cur_depth)
        if cur_depth > max_depth:
            raise RecursionError('Depth of decode tree too deep. Max=%i.' % max_depth)

        if data[start] == ord('\x00'):
            return None, start + 1

        if data[start] == ord('T') or data[start] == ord('F'):
            return (data[start] == ord('T')), start + 1

        if data[start] == ord('i'):
            end = data.find(ord(';'), start)

            try:
                return int(data[start+1:end], 10), end + 1
            except ValueError:
                raise DecodingError("Expected integer number (or ';')", start+2) from None

        if data[start] == ord('f'):
            end = data.find(ord(';'), start)

            if end == -1: raise DecodingError('End of float not found', start)

            try:
                return float(data[start+1:end]), end + 1
            except:
                raise DecodingError('Could not convert float', start) from None

        if data[start] == ord('l'):
            cur_depth += 1
            res = []
            start += 1

            try:
                while data[start] != ord(';'):
                    elem, start = decode_next(start)
                    res.append(elem)
            except IndexError:
                raise DecodingError('Unexpected end of list (no end) ', start-1) from None

            cur_depth -= 1


            return res, start + 1

        if data[start] == ord('d'):
            cur_depth += 1
            res = {}
            start += 1

            try:
                while data[start] != ord(';'):
                    key, start = decode_next(start)
                    value, start = decode_next(start)
                    res[key] = value
            except IndexError:
                raise DecodingError('Unexpected end of dict (no end) ', start-1) from None

            cur_depth -= 1
            return res, start + 1


        if data[start] == ord('p'):
            name_end = data.find(b'|', start+1)
            name = str(data[start+1:name_end], 'utf-8')

            type_byte = chr(data[name_end+1])
            try: type_ = [t for t in types if t.repr==type_byte][0]
            except: raise DecodingError('Could not determin the type of the property', name_end+1)

            p = Property(name, type_)

            try:
                p.value, meta_start = decode_next(name_end+3)
            except DecodingError:
                raise DecodingError('Could not get propety value, format incorrect', name_end+3)

            p.meta, last = decode_next(meta_start+1)

            return p, last + 1

        if data[start] == ord('$'): # action param
            name_end = data.find(b'|', start+1)
            name = str(data[start+1:name_end], 'utf-8')

            type_byte = chr(data[name_end+1])
            try: type_ = [t for t in types if t.repr==type_byte][0]
            except: raise DecodingError('Could not determin the type of the paramerter', name_end+1)

            ap = ActionParameter(name, type_)
            ap.meta, end = decode_next(name_end+3)

            return ap, end + 1

        if data[start] == ord('^'): # action '^%s(%joined-list)%s;'
            name_end = data.find(b'(', start+1)
            name = str(data[start+1:name_end], 'utf-8')

            a = Action(name)

            start = name_end + 1

            cur_depth += 1
            while data[start] != ord(')'):
                if data[start] != ord('$'):
                    raise DecodingError('Expected action parameter or end of parameters', start)

                ap, start = decode_next(start)
                a.action_parameters.append(ap)
            cur_depth -= 1

            try:
                type_byte = chr(data[start + 1])
                type_ = [t for t in types if t.repr==type_byte][0]
            except: raise DecodingError('Could not determin the return type of the action', name_end+1)


            return a, start + 3 # 3 -> ')T;'

        if data[start:start+4] == b'node': # node
            n = BaseNode()
            start += 5

            cur_depth += 1
            try:
                while data[start] != ord('|'): # get props
                    p, start = decode_next(start)
                    n.add_property(p)
            except: raise DecodingError('Issue parsing node properties', start) from None
            cur_depth -= 1

            start += 1 # skip over pipe to action section


            cur_depth += 1
            try:
                while data[start] != ord('|'): # get actions
                    a, start = decode_next(start)
                    n.add_action(a)
            except: raise DecodingError('Issue parsing node actions', start)
            cur_depth -= 1

            try: n.node_info, start = decode_next(start+1)
            except DecodingError: raise DecodingError('Could not parse node info') from None

            return n, start + 1


        # if gets here, its a string('s') or bytes('z')
        if data[start:start+1] not in b'sz':
            error_message = "'%s' charater not valid as encoding object start" % chr(data[start]),
            raise DecodingError(error_message, start) from None

        lenend = data.find(ord(':'), start)

        try: length = int(data[start+1:lenend], 10)
        except ValueError: raise DecodingError("Could not get length of string or bytes", start) from None


        end = lenend + length + 1

        value = data[lenend+1:end]

        if data[start] == ord('s'): # normal string
            value = str(value, 'utf-8')
        # else byte string ('z') as , retain bytestring

        return value, end


    try:
        return decode_next(0)[0]
    except RecursionError as e:
        too_deep = e
    except DecodingError as e:
        raise DecodingError(e) from None
    except:
        raise DecodingError('Unknown encoding error') from None

    if too_deep: # only reached on RecursionError
        raise RecursionError(too_deep)















# concept (therefore incomplete) for a non-recursive algorithm
# useful when stack is limited (such as when porting to c for embeded)
def __non_recursive_encode_concept(obj):
    class _semicolon(): # simulating type def
        pass
    semicolon = _semicolon()

    # obj = {'a':[42]}
    it = [obj] # itterator array for queing encoding

    out = ""

    for o in it:
        if type(o) == _semicolon:
            out += ';'
            continue

        if type(o) == str:
            out += 's' + str(len(o)) + ':' + o

        if type(o) == int:
            out += 'i' + str(o) + ';'
            continue

        if type(o) == list:
            out += 'l'
            it += o # add list items to itterator
            it.append(semicolon) # tell loop when list is done
            continue

        if type(o) == dict:
            out += 'd'
            for key, value in o.items():
                it += [key, value] # add to it as key,val,key,val
            it.append(semicolon)
            continue


    print(out)

# i tried breifly and could not figure it out shortly, may try again later
def __non_recursive_decode_concept(data:bytes):
    pass
    # i tried breifly and could not figure it out shortly, may try again later

    enc = b'li1;i2;i3;;'

    out = None

    cur_out = None

    for c in enc:

        if c == ord('l'):
            cur_out = []

        if c == ord('i'):
            if type(cur_out) == list:
                pass
