import json
import os
import re
import time
from contextlib import closing
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address

from ipmininet.clean import cleanup
from ipmininet.ipnet import IPNet
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import RouterConfig, ExaBGPDaemon, AF_INET, AF_INET6, \
    ebgp_session, BGPRoute, BGPAttribute, ExaList, BGP
from ipmininet.tests import require_root

exa_routes = {
    'ipv4': [
        BGPRoute(ip_network('8.8.8.0/24'), [BGPAttribute("next-hop", "self"),
                                            BGPAttribute("as-path", ExaList([1, 56, 97])),
                                            BGPAttribute("med", 42),
                                            BGPAttribute("origin", "egp")]),
        BGPRoute(ip_network('30.252.0.0/16'), [BGPAttribute("next-hop", "self"),
                                               BGPAttribute("as-path", ExaList([1, 48964, 598])),
                                               BGPAttribute("med", 100),
                                               BGPAttribute("origin", "incomplete"),
                                               BGPAttribute("community", ExaList(["1:666", "468:45687"]))]),
        BGPRoute(ip_network('1.2.3.4/32'), [BGPAttribute("next-hop", "self"),
                                            BGPAttribute("as-path", ExaList([1, 49887, 39875, 3, 4])),
                                            BGPAttribute("origin", "igp"),
                                            BGPAttribute("local-preference", 42)])
    ],
    'ipv6': [
        BGPRoute(ip_network("dead:beef:15:dead::/64"), [BGPAttribute("next-hop", "self"),
                                                        BGPAttribute("as-path", ExaList([1, 4, 3, 5])),
                                                        BGPAttribute("origin", "egp"),
                                                        BGPAttribute("local-preference", 1000)]),
        BGPRoute(ip_network("bad:c0ff:ee:bad:c0de::/80"), [BGPAttribute("next-hop", "self"),
                                                           BGPAttribute("as-path", ExaList([1, 3, 4])),
                                                           BGPAttribute("origin", "egp"),
                                                           BGPAttribute("community",
                                                                        ExaList(
                                                                            ["2914:480", "2914:413", "2914:4621"]))]),
        BGPRoute(ip_network("1:5ee:bad:c0de::/64"), [BGPAttribute("next-hop", "self"),
                                                     BGPAttribute("as-path", ExaList([1, 89, 42, 5])),
                                                     BGPAttribute("origin", "igp")])
    ]
}


class ExaBGPTopo(IPTopo):
    def build(self, *args, **kwargs):
        """
          +---+---+---+     +---+---+---+
          |           |     |           |
          |    as1    |     |    as2    |
          |   ExaBGP  +-----+  FRR BGP  |
          |           |     |           |
          +---+---+---+     +---+---+---+
        """

        af4 = AF_INET(routes=exa_routes['ipv4'])
        af6 = AF_INET6(routes=exa_routes['ipv6'])

        # Add all routers
        as1 = self.addRouter("as1", config=RouterConfig, use_v4=True, use_v6=True)
        as1.addDaemon(ExaBGPDaemon, address_families=(af4, af6))

        as2 = self.bgp('as2')

        # Add links
        las12 = self.addLink(as1, as2)
        las12[as1].addParams(ip=("10.1.0.1/24", "fd00:12::1/64",))
        las12[as2].addParams(ip=("10.1.0.2/24", "fd00:12::2/64",))

        # Set AS-ownerships
        self.addAS(1, (as1,))
        self.addAS(2, (as2,))
        # Add eBGP peering
        ebgp_session(self, as1, as2)

        super().build(*args, **kwargs)

    def bgp(self, name):
        r = self.addRouter(name, use_v4=True, use_v6=True)
        r.addDaemon(BGP, debug=('updates', 'neighbor-events', 'zebra'), address_families=(
            AF_INET(redistribute=('connected',)),
            AF_INET6(redistribute=('connected',))))
        return r


@require_root
def test_correct_rib_as2():
    get_rib = "#!/usr/bin/env sh \n" \
              "nc {host} {port} <<EOF\n" \
              "zebra\n" \
              "show bgp {family} json\n" \
              "exit\n" \
              "EOF\n"

    to_unlink = list()

    for family in ('ipv4', 'ipv6'):
        super_path = "/tmp/_get_%s_rib.sh" % family
        to_unlink.append((super_path, family))
        with closing(open(super_path, 'w')) as f:
            f.write(get_rib.format(host="localhost", port=2605, family=family))

    try:
        net = IPNet(topo=ExaBGPTopo())
        net.start()

        # Must wait at least 120s as ExaBGP waits 2 minutes at most before sending its entire RIB
        time.sleep(130)
        frr_bgp_node = net['as2']

        for command, family in to_unlink:
            my_output = frr_bgp_node.popen("sh %s" % command)
            my_output.wait()
            out, err = my_output.communicate()

            output = out.decode(errors="ignore")

            p = re.compile(r"(?s)as2> show bgp {family} json(?P<rib>.*)as2> exit".format(family=family))
            m = p.search(output)

            assert m is not None, "Unable to find the RIB"

            my_rib = m.group("rib")
            parsed_rib = json.loads(my_rib)
            rib_routes = parsed_rib['routes']

            print(rib_routes)

            for our_route in exa_routes[family]:

                str_ipnet = str(our_route.IPNetwork)
                rib_route = rib_routes[str_ipnet][0]  # take the first one as ExaBGP sends only one route per prefix

                assert str_ipnet in rib_routes, \
                    "{route} not in FRRouting BGP RIB".format(route=our_route.IPNetwork)

                assert rib_route["origin"].lower() == our_route['origin'].val, \
                    "Bad origin for route {route}. Expected {origin_expect}. Received {origin_real}" \
                        .format(route=our_route.IPNetwork, origin_expect=our_route['origin'].val,
                                origin_real=rib_route["origin"])

                check_as_path(rib_route["path"], our_route['as-path'].val)

                assert check_next_hop(rib_route['nexthops']) is True, \
                    "Bad next hop"

                if 'metric' in rib_route:
                    assert rib_route['metric'] == our_route['med'].val, \
                        "Bad MED. Expected {expected}. Received {received}" \
                            .format(expected=our_route['med'].val, received=rib_route['metric'])

        net.stop()
    finally:
        for file, family in to_unlink:
            os.unlink(file)

        cleanup()


def check_next_hop(next_hops: dict):
    our_next_hop = {
        'ipv4': ip_address("10.1.0.1"),
        'ipv6': ip_address("fd00:12::1")
    }

    for next_hop in next_hops:
        rib_next_hop = ip_address(next_hop['ip'])

        if isinstance(rib_next_hop, IPv4Address):
            if rib_next_hop == our_next_hop['ipv4']:
                return True
        elif isinstance(rib_next_hop, IPv6Address):
            if rib_next_hop == our_next_hop['ipv6']:
                return True

    return False


def check_as_path(as_path_rib: str, as_path_us: ExaList):
    as_rib = as_path_rib.split(" ")
    as_rib_us = as_path_us.val

    error_msg = "Bad AS-PATH. Expected {expected}. Received {received}"

    assert len(as_rib) == len(as_rib_us), error_msg. \
        format(expected=as_rib_us, received=as_path_rib)

    for idx, asn_received, asn_expected in zip(range(len(as_rib)), as_rib, as_rib_us):
        assert asn_received == asn_received, "Bad ASN at index {index}. Expected AS{expected}. Received AS{received}". \
            format(index=idx, expected=asn_expected, received=asn_received)
