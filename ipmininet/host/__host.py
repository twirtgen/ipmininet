"""This modules defines a host class,
   with a modular config system."""
from typing import Type, Union, Tuple, Dict, Optional

import mininet.node as _m

from ipmininet.link import IPIntf
from ipmininet.router import IPNode
from ipmininet.host.config.base import HostConfig
from ipmininet.utils import realIntfList


class IPHost(IPNode):
    """A Host which manages a set of daemons"""

    def __init__(self, name,
                 config: Union[Type[HostConfig],
                               Tuple[Type[HostConfig], Dict]] = HostConfig,
                 *args, **kwargs):
        super().__init__(name, config=config, *args, **kwargs)

    def setDefaultRoute(self, intf: Optional[Union[IPIntf, str]] = None,
                        v6=False):
        """Set the default routes to go through the intfs.
           intf: Intf or {dev <intfname> via <gw-ip> ...}"""
        if intf is None:
            return

        if isinstance(intf, str) and " " in intf:
            params = intf

            # Recover interface
            option_list = params.split(" ")
            for i, opt in enumerate(option_list):
                if opt == "dev":
                    intf = self.intf(option_list[i+1])
        else:
            params = "dev %s" % intf

        # Set command to be re-executed if interface is downed
        # and then brought back up
        version = "6" if v6 else "4"
        cmd = "ip -{ver} route del default;" \
              " ip -{ver} route add default {params}".format(ver=version,
                                                             params=params)
        if isinstance(intf, IPIntf):
            intf.restore_cmds.append(cmd)
        self.cmd(cmd)

    def createDefaultRoutes(self):
        if 'defaultRoute' in self.params:
            return True

        # The first router we find will become the default gateway
        found = False
        for itf in realIntfList(self):
            for r in itf.broadcast_domain.routers:
                if self.use_v4 and self.use_v4 and len(r.addresses[4]) > 0:
                    self.setDefaultRoute("dev {} via {}".format(itf.name,
                                                                r.ip),
                                         v6=False)
                    found = True
                if self.use_v6 and self.use_v6 and len(r.addresses[6]) > 0 \
                        and len(r.ra_prefixes) == 0:
                    # We define a default route only if router
                    # advertisements are not activated. If we call the same
                    # function, the route created above might be deleted
                    self.setDefaultRoute("dev {} via {}".format(itf.name,
                                                                r.ip6),
                                         v6=True)
                    found = True
                break
            if found:
                return True
        return False


CPULimitedHost = _m.CPULimitedHost
CPULimitedHost.__bases__ = (IPHost,)
