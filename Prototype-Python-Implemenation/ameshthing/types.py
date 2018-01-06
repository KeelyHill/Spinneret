from collections import namedtuple

# test = namedtuple('test', ['a', 'next'])

type_T = namedtuple('type_T', ['name', 'repr', 'pytype'])
type_T.__repr__ = lambda s: 'type_T(%s,%s)' % (s.name, s.repr)

types = namedtuple('types', ['string', 'int', 'float', 'bool', 'list', 'dict', 'null', 'binnary'])


types = types(
    type_T('string', 's', str),
    type_T('int', 'i', int),
    type_T('float', 'f', float),
    type_T('bool', 'b', bool),
    type_T('list', 'l', list),
    type_T('dict', 'd', dict),
    type_T('null', 'n', None),
    type_T('binary', 'z', bytes),

    # IDEA possible integer addtions
    # type_T('uint', 'iu')
    # type_T('uint8', 'hu') # maybe just h, assume unsigned
    # type_T('int16', 'H')
    # type_T('uint16', 'Hu')
)




# IDEA: decide if I want to be this strict about keys, is so implement
class MetadataDict(dict):
    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __getitem__(self, key):
        val = dict.__getitem__(self, key)
        return val

    def __setitem__(self, key, val):

        if key not in ['a', 'c']:
            raise Exception('`%s` not a valid metadata key' % key)

        dict.__setitem__(self, key, val)
