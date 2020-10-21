import ipaddress
import itertools
import random

from ipmininet.iptopo import IPTopo
from ipmininet.router.config import SHARE, ebgp_session, RouterConfig, BGP, ExaBGPDaemon, BGPRoute, BGPAttribute, \
    ExaList
import ipmininet.router.config.bgp as _bgp

__MAX_UINT32_ = 4294967295


def list_of_rnd_lists(nb, max_sub_rnd_list):
    def random_gen(low, high):
        while True:
            yield random.randrange(low, high)

    rnd_lists = []

    for _ in range(0, nb):
        rnd_set = set()
        gen = random_gen(1, 65536)
        rnd_path_len = random.randint(1, max_sub_rnd_list)

        # Try to add elem to set until set length is less than 'rnd_path_len'
        for x in itertools.takewhile(lambda y: len(rnd_set) <= rnd_path_len, gen):
            rnd_set.add(x)

        rnd_lists.append(list(rnd_set))

    return rnd_lists


def rnd_list(max_sub_rnd_list, strict=False):
    def random_gen(low, high):
        while True:
            yield random.randrange(low, high)

    rnd_set = set()
    gen = random_gen(1, 65536)
    rnd_path_len = random.randint(1, max_sub_rnd_list) if not strict else max_sub_rnd_list

    for x in itertools.takewhile(lambda y: len(rnd_set) <= rnd_path_len, gen):
        rnd_set.add(x)

    return list(rnd_set)


def build_bgp_route(ip_networks):

    my_routes = list()

    for ip_network in ip_networks:
        next_hop = BGPAttribute("next-hop", "self")
        as_path = BGPAttribute("as-path", ExaList(rnd_list(random.randint(1, 25))))
        communities = BGPAttribute("community",
                                   ExaList(["%d:%d" % (j, k) for j, k in zip(rnd_list(24, True), rnd_list(24, True))]))
        med = BGPAttribute("med", random.randint(1, __MAX_UINT32_))
        origin = BGPAttribute("origin", random.choice(["igp", "egp", "incomplete"]))

        my_routes.append(BGPRoute(ip_network, [next_hop, origin, med, as_path, communities]))

    return my_routes


class ExaBGPTopoInjectPrefixes(IPTopo):
    """This topology builds a 4-AS network exchanging BGP reachability as shown
    in the figure below. Shared cost are described with ' = ',
    client - provider with ' $ '.

    ASes always favor routes received from clients, then routes from shared-cost
    peering, and finally, routes received from providers.
    This is not influenced by the AS path length.

    This topology is taken from
    https://www.computer-networking.info/exercises/html/ex-routing-policies.html
    """

    @staticmethod
    def gen_simple_prefixes():
        pfxs = (ipaddress.ip_network("8.8.8.0/24"),
                ipaddress.ip_network("19.145.206.163/32"),
                ipaddress.ip_network("140.182.0.0/16"),
                ipaddress.ip_network("c0ff:ee:beef::/56"),
                ipaddress.ip_network("1:ea7:dead:beef::/64"),
                ipaddress.ip_network("d0d0:15:dead::/48"))

        return build_bgp_route(pfxs)

    def build(self, *args, **kwargs):
        """
         +--+--+     +--+--+
         | as1 +-----+ as2 |
         +--+--+  =  +--+--+
        """
        # Add all routers
        as1r1 = self.addRouter("as1_rr1", config=RouterConfig, use_v4=True, use_v6=True)
        as1r1.addDaemon(ExaBGPDaemon, prefixes=self.gen_simple_prefixes())

        as2r1 = self.bgp('as2')

        # Add links
        las12 = self.addLink(as1r1, as2r1)
        las12[as1r1].addParams(ip=("fd00:12::1/64",))
        las12[as2r1].addParams(ip=("fd00:12::2/64",))

        # Set AS-ownerships
        self.addAS(1, (as1r1,))
        self.addAS(2, (as2r1,))
        # Add eBGP peering
        ebgp_session(self, as1r1, as2r1, link_type=SHARE)

        # Add test hosts
        for r in self.routers():
            self.addLink(r, self.addHost('h%s' % r))
        super().build(*args, **kwargs)


    def bgp(self, name):
        r = self.addRouter(name, use_v4=True, use_v6=True)
        r.addDaemon(BGP, address_families=(
            _bgp.AF_INET(redistribute=('connected',)),
            _bgp.AF_INET6(redistribute=('connected',))))
        return r
