Using the link failure simulator tool
=====================================

To check the routing configuration of the network, it may be useful
to check if the failure of any link in the topology does not break
the network. That is, the failure causes the network to
recompute the best path for any destination and therefore
any destination is still reachable.

To simulate a link failure, IPmininet proposes the following functions:

.. automethod:: ipmininet.ipnet.IPNet.runFailurePlan
    :noindex:
.. automethod:: ipmininet.ipnet.IPNet.randomFailure
    :noindex:
.. automethod:: ipmininet.ipnet.IPNet.restoreIntfs
    :noindex:

The following code shows an example on how using those different tools
to simulate failure scenarios. The link failure simulation is started
after the network has been built, when calling ``post_build()``.

.. testcode:: linkfailure

    from ipmininet.iptopo import IPTopo
    from ipmininet.utils import realIntfList


    class MyTopology(IPTopo):
        """

            +-----+                 +------+
            |  r1 +-----------------+  r2  |
            +---+-+                 +---+--+
                |        +-----+        |
                +--------| r3  |--------+
                         +--+--+
                            |
                         +--+--+
                         | r4  |
                         +-----+
        """

        def build(self, *args, **kwargs):
            r1 = self.addRouter("r1")
            r2 = self.addRouter("r2")
            r3 = self.addRouter("r3")
            r4 = self.addRouter("r4")
            self.addLinks((r1, r2), (r2, r3), (r3, r1), (r3, r4))
            super().build(*args, **kwargs)

        def post_build(self, net):
            # Run the failure plan and then, restore the links
            failure_plan = [("r1", "r2"), ("r3", "r4")]
            interfaces_down = net.runFailurePlan(failure_plan)
            net.restoreIntfs(interfaces_down)

            # Run a random failure with 2 link to be downed and then, restore them
            interfaces_down = net.randomFailure(2)
            net.restoreIntfs(interfaces_down)

            # Run a 1 link Failure Random based on a given list of link and then, restore the link
            links = list(map(lambda x: x.link, realIntfList(net["r1"])))
            interfaces_down = net.randomFailure(1, weak_links=links)
            net.restoreIntfs(interfaces_down)
            super().post_build(net)

This is a simple example. It is possible to check if two nodes are still reachable
by using basic functions such as ``pingAll()``, or doing more precise tests by
starting a basic TCP client/server on the nodes.

We use the ``post_build()`` function to use methods related to the simulation
of a link failure. However, since those methods are belonging to the ``IPNet``
class, they can be used outside ``post_build()`` as long as the ``IPNet``
object can be accessed.


.. doctest related functions


.. testsetup:: *

    from ipmininet.clean import cleanup
    cleanup(level='warning')

.. testcode:: *
    :hide:

    try:
        MyTopology
    except NameError:
        MyTopology = None

    if MyTopology is not None:
        from ipmininet.ipnet import IPNet
        net = IPNet(topo=MyTopology())
        net.start()

.. testcleanup:: *

    try:
        net
    except NameError:
        net = None

    if net is not None:
        net.stop()
