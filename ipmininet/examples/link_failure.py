from ipmininet.iptopo import IPTopo

class FailureTopo(IPTopo):
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

    def build(self,*args,**kwargs):
        r1 = self.addRouter("r1")
        r2 = self.addRouter("r2")
        r3 = self.addRouter("r3")
        r4 = self.addRouter("r4")
        self.addLinks((r1, r2), (r2, r3), (r3, r1), (r3, r4))
        super().build(*args, **kwargs)

    def post_build(self, net):
        failure_plan = [("r1","r2"),("r3","r4")]
        ## Run the failure plan then restore it
        interfaces_down = net.runFailurePlan(failure_plan)
        net.restoreLink(interfaces_down)
        ## Run a random failure with 2 link to be downed then restore it
        interfaces_down = net.RandomFailure(2)
        net.restoreLink(interfaces_down)
        ## Run a 1 link Failure Random based on a given list of link
        weak_node = net.get("r1")
        intfs = weak_node.intfList()
        for intf in enumerate(intfs):
            intfs[intf[0]] = intf[1].link
        interfaces_down = net.RandomFailure(1, weak_links=intfs[1:]) #use to not down the lo interface
        net.restoreLink(interfaces_down)
        super().post_build(net)
        
