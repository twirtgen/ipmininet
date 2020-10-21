"""" This module test the Linkfailure api """

from ipmininet.clean import cleanup
from ipmininet.ipnet import IPNet
from ipmininet.iptopo import IPTopo
from ipmininet.tests.utils import assert_connectivity
import time
from . import require_root

class Topo(IPTopo):

    def build(self, *args, **kwargs):
        r1 = self.addRouter("r1")
        r2 = self.addRouter("r2")
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")

        self.addLinks((r1,r2), (h1,r1), (h2,r2))



"""@require_root
def test_failurePlan():
    try:
        failure_plan = [("r1", "r2")]
        net = IPNet(topo=Topo())
        net.start()
        time.sleep(20) #otherwise ospf still not converged
        assert 0.0 == net.pingAll()
        interface_down = net.runFailurePlan(failure_plan)
        assert 100.0 == net.pingAll()
        net.restoreLink(interface_down)
        time.sleep(20)
        assert 0.0 == net.pingAll()
        net.stop()
    finally:
        cleanup()
"""
@require_root
def test_randomFailure():
    try:
        net = IPNet(topo=Topo())
        net.start()
        time.sleep(20)
        assert 0.0 == net.pingAll()
        interface_down = net.RandomFailure(1)
        assert 100.0 == net.pingAll()
        net.restoreLink(interface_down)
        time.sleep(20)
        assert 0.0 == net.pingAll()
        net.stop()
    finally:
        cleanup()

"""@require_root
def test_randomFailureOnTargetedLink():
    try:
        net = IPNet(topo=Topo())
        net.start()
        time.sleep(20)
        assert 0.0 == net.pingAll()
        node = net.get("r1")
        interfaces = node.intfList()
        interfaces = [interfaces[1].link] #use to not have to lo interface
        interface_down = net.RandomFailure(1,weak_links=interfaces)
        assert 100.0 == net.pingAll()
        net.restoreLink(interface_down)
        time.sleep(20)
        assert 0.0 == net.pingAll()
        net.stop()
    finally:
        cleanup()
"""

