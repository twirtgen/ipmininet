%for n in node.exabgp.neighbors:

neighbor ${n.peer} {
    description ${n.description};
    router-id ${node.exabgp.routerid};
    local-address ${n.local_addr};
    local-as ${node.exabgp.asn};
    peer-as ${n.asn};
    listen ${node.exabgp.port};
    connect ${n.port};

    family {
    %for af in node.exabgp.address_families:
        ${af.name} unicast;
    %endfor
    }
    %if len(node.exabgp.prefixes) > 0:

    static {
        %for pfx in node.exabgp.prefixes:
        ${str(pfx)};
        %endfor
    }
    %endif
}
%endfor