from abc import ABC, abstractmethod
from typing import Optional, Sequence, Union, List

from .bgp import AbstractBGP, AF_INET, AF_INET6, BGP_DEFAULT_PORT, Peer
from .utils import ConfigDict


class Representable(ABC):
    """
    String representation for ExaBGP configuration
    """

    @abstractmethod
    def __str__(self):
        raise NotImplementedError


class HexRepresentable(Representable):
    @abstractmethod
    def hex_repr(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def __str__(self):
        raise NotImplementedError


class ExaList(HexRepresentable):
    def hex_repr(self) -> str:
        raise ValueError("Must not be used for an Hexadecimal representation")

    def __init__(self, lst: List[Union[int, str]]):
        assert isinstance(lst, list), "%s is not a list" % type(lst)
        self.lst = lst

    def __str__(self) -> str:
        return "[ %s ]" % ' '.join([str(it) for it in self.lst])


class BGPAttributeFlags(HexRepresentable):

    @staticmethod
    def to_hex_flags(a, b, c, d):
        return (((a << 3) & 8) | ((b << 2) & 4) | ((c << 1) & 2) | (d & 1)) << 4

    def __init__(self, optional, transitive, partial, extended):
        allowed_vals = {0, 1}
        assert optional in allowed_vals
        assert transitive in allowed_vals
        assert partial in allowed_vals
        assert extended in allowed_vals

        self.optional = optional
        self.transitive = transitive
        self.partial = partial
        self.extended = extended

        self._hex = self.to_hex_flags(self.optional, self.transitive, self.partial, self.extended)

    def __str__(self):
        return self.hex_repr()

    def hex_repr(self):
        return f"0X{self._hex:X}"

    def __repr__(self):
        return "BGPAttributeFlags(opt=%d, transitive=%d, partial=%d, ext=%d, _hex=%s (%s))" % (
            self.optional, self.transitive, self.partial, self.extended, hex(self._hex), bin(self._hex))


class BGPAttribute(Representable):
    """
    A BGP attribute as represented in ExaBGP. Either the Attribute is known from ExaBGP
    and so the class uses its string representation. Or the attribute is not known, then
    the class uses its hexadecimal representation. The latter representation is also useful
    to modify flags of already known attribute. For example the MED value is a known attribute
    which is not transitive. By passing a BGPAttributeFlags object to the constructor, it is
    now possible to make is transitive with BGPAttributeFlags(1, 1, 0, 0) (both optional and
    transitive bits are set to 1)
    """

    @property
    def _known_attr(self):
        return {'next-hop', 'origin', 'med',
                'as-path', 'local-preference', 'atomic-aggregate',
                'aggregator', 'originator-id', 'cluster-list',
                'community', 'large-community', 'extended-community',
                'name', 'aigp'}

    def hex_repr(self) -> str:
        return "attribute [ {type} {flags} {value} ]".format(
            type=hex(self.type),
            flags=self.flags.hex_repr(),
            value=self.val.hex_repr())

    def str_repr(self) -> str:
        return "{type} {value}".format(type=str(self.type), value=str(self.val))

    def __init__(self, attr_type: Union[str, int], val: Union['HexRepresentable', int, str],
                 flags: Optional['BGPAttributeFlags'] = None):
        """
        Constructs an Attribute known from ExaBGP or an unknown attribute if flags is
        not None.

        :param attr_type: In the case of a Known attribute, attr_type is a valid string
        recognised by ExaBGP. In the case of an unknown attribute, attr_type is the interger
        ID of the attribute.
        :param val: The actual value of the attribute
        :param flags: If None, the BGPAttribute object contains a known attribute from ExaBGP.
        In this case, the representation of this attribute will be a string.
        If flags is an instance of BGPAttribute, the hexadecimal representation will be used
        :raise ValueError if the initialisation of BGPAttribute fails. Either because type_attr
        is not an int (for an unknown attribute), or the string of type_attr is not recognised
        by ExaBGP (for a known attribute)
        """

        if flags is None:
            if str(attr_type) not in self._known_attr:
                raise ValueError("{unk_attr} is not a known attribute".format(unk_attr=str(attr_type)))
        else:
            assert isinstance(val, HexRepresentable)

        self.flags = flags
        self.type = attr_type
        self.val = val

    def __str__(self):
        if self.flags is None:
            return self.str_repr()
        else:
            return self.hex_repr()

    def __repr__(self) -> str:
        return "BGPAttribute(attr_type={attr_type}, val={val}{flags})".format(
            attr_type=self.type, val=self.val,
            flags=" flags={val}".format(val=self.flags.hex_repr() if self.flags is not None else ""))


class BGPRoute(Representable):

    def __init__(self, network: 'Representable', attributes: Sequence['Representable']):
        self.IPNetwork = network
        self.attributes = attributes

    def __str__(self):
        route = "unicast {prefix}".format(prefix=str(self.IPNetwork))
        for attr in self.attributes:
            route += " %s" % str(attr)

        return route


class ExaBGPDaemon(AbstractBGP):
    NAME = "exabgp"
    KILL_PATTERNS = (NAME,)

    def __init__(self, node, port=BGP_DEFAULT_PORT, *args, **kwargs):
        super().__init__(node=node, *args, **kwargs)
        self.port = port

    def build(self):
        cfg = super().build()
        cfg.asn = self._node.asn
        cfg.port = self.port
        cfg.neighbors = self._build_neighbors()
        cfg.address_families = self._address_families(
            self.options.address_families, cfg.neighbors)
        self.options.base_env.update(self.options.env)
        cfg.env = self.options.base_env

        return cfg

    @property
    def STARTUP_LINE_EXTRA(self):
        return ''

    @property
    def env_filename(self):
        return self._file('env')

    @property
    def cfg_filenames(self):
        return super().cfg_filenames + [self.env_filename]

    @property
    def template_filenames(self):
        return super().template_filenames + ["%s_env.mako" % self.NAME]

    @property
    def startup_line(self) -> str:
        return '{name} --env {env} {conf}' \
            .format(name=self.NAME,
                    env=self.env_filename,
                    conf=self.cfg_filename)

    @property
    def dry_run(self) -> str:
        return '{name} --validate --env {env} {conf}' \
            .format(name=self.NAME,
                    env=self.env_filename,
                    conf=self.cfg_filename)

    def set_defaults(self, defaults):
        defaults.base_env = ConfigDict(
            daemon=ConfigDict(
                user='root',
                drop='false',
                daemonize='false',
                pid=self._file('pid')
            ),
            log=ConfigDict(
                # all='true',
                level='DEBUG',
                destination=self._file('log'),
                reactor='true',
                processes='true',
                network='true',
            ),
            api=ConfigDict(
                cli='false',
            ),
            tcp=ConfigDict(
                delay=2
            )
        )
        defaults.address_families = [AF_INET(), AF_INET6()]
        defaults.env = ConfigDict()
        super().set_defaults(defaults)
