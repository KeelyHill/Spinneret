from .types import type_T, types

from .exceptions import ArgumentValidationError


BAD_NAME_CHARS = "{}()[]|:;+,.=><%$#@!?^`*'\\\"/~'\x20'"


class BaseConstruct():
    """
    Provides a base class for the standard functionality
    of Actions and Properties.
    """

    __slots__ = '_name', '_type', 'meta'

    @property
    def name(self):
        return self._name

    @property
    def type_T(self):
        return self._type

    def __init__(self, name:str, type_):
        if name in BAD_NAME_CHARS and name != '':
            raise Exception('Name can not be empty.')
        self._name = name

        if type(type_) != type_T:
            raise Exception('`type_` must be of type `type_T`')

        self._type = type_

        self.meta = {}

class Property(BaseConstruct):
    __slots__ = 'value'

    def __init__(self, name:str, type_, value=None):
        super().__init__(name, type_)
        self.value = value

    def __repr__(self):
        # return "Property at " + str(hex(id(self)))
        return 'Property<%s:%s=%s>' % (self._name, self._type.name, str(self.value))


class ActionParameter(BaseConstruct):
    __slots__ = 'optional' # unsure for v0.1

    def __init__(self, name:str, type_, meta={}):
        super().__init__(name, type_)

        self.meta = meta


    def __repr__(self):
        return (
            'Act-Paramerter<%s:%s, %s>' %
                # ('?' if self.optional else '',
                (self.name, self._type.name,
                'meta' if self.meta else 'no meta')
        )



class Action(BaseConstruct):
    # __slots__ = ''

    # helper property, the return type name more obvious than type_T
    return_type = property(lambda s: s.type_T)

    def __init__(self, name:str, callback=None, action_parameters:list=[], return_type=types.null):
        super().__init__(name, return_type)
        """Action
        :callback: a function to run when requested. Any returned value will get returned in a RESP.
            Tuples second value will be interpreted as a dict of addition properties for the RESP.
            >>> return (None, ['on', 'color']) # reponse to include values of `on` and `color`
        """

        if callback != None and not hasattr(callback, '__call__'):
            raise Exception('`callback` not callable')
        self.callback = callback

        self.action_parameters = action_parameters if action_parameters else []

    def __repr__(self):
        param_short_repr = ','.join([a.name + ':' + a.type_T.repr for a in self.action_parameters])
        return '<Action %s(%s)->%s>' % (self._name, param_short_repr, self._type.name)

    def validate_args(self, *args):
        # test for correct number of arguments
        if len(args) != len(self.action_parameters):
            raise ArgumentValidationError('Not correct amount of arguments. %i found, %i expected'
                    % (len(args), len(self.action_parameters)))

        # test for correct types
        for i in range(len(args)):
            arg = args[i]
            param = self.action_parameters[i]

            if arg != None:
                if type(arg) != param.type_T.pytype:
                    raise ArgumentValidationError("Argument for '%s' should be '%s'" % (param.name, param.type_T.repr))


        # TODO add meta verification when I work out meta


    def run(self, *args):
        if self.callback != None:
            return self.callback(*args)
        else:
            raise TypeError('Callback never assigned.\n(One cannot call actions for another node, must requet it.)')



class BaseNode():
    """Most basic node used for special encoding. Inheritance not recomended."""

    def __init__(self):

        self._node_info = {}

        self.properties = {}
        self.actions = {}

    network_addr = property(lambda s:s.node_info['addr'])


    @property
    def node_info(self):
        return self._node_info
    @node_info.setter
    def node_info(self, new):
        self._node_info = new


    def __repr__(self):
        return 'Node<props=%s, actions=%s>' % (
            str(list(self.properties.keys())),
            str(list(self.actions.keys()))
        )

    def property_named(self, name:str, ensure_public=True):
        """Returns a property object if exists, `None` if not
        Returns `None` if 'ensure_public=True' and underscore on first charater of name.
        """

        if ensure_public and name.startswith('_'):
            return None
        return self.properties.get(name, None)

    def action_named(self, name:str):
        return self.actions.get(name, None)


    def add_property(self, prop:Property):
        """Adds a Property object to the nodes properties dict."""

        if prop.name in self.properties:
            raise Exception('Property already exists.')
        self.properties[prop.name] = prop

        return self.properties[prop.name]

    def add_action(self, act:Action):
        """Adds an Action object to the nodes properties dict."""

        if act.name in self.actions:
            raise Exception('Action already exists.')
        self.actions[act.name] = act

        return self.actions[act.name]

    def validate_node_info(self):
        required_keys = ['addr', 'kVerify', 'kPublic', 'netTime', 'v', 'capabilities']

        missing_keys = [k for k in required_keys if not k in self.node_info]

        if len(missing_keys) > 0:
            raise Exception('%s keys required in `node_info` dict.' % str(missing_keys))
            return False

        return True
