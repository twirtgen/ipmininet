%for n in node.exabgp.neighbors:
neighbor ${n.peer} {
    description ${n.description};
    router-id ${node.exabgp.routerid};
    local-address ${n.local_addr};
    local-as ${node.exabgp.asn};
    peer-as ${n.asn};
    listen ${node.exabgp.port};
    connect ${n.port};

    group-updates false;

    family {
    %for af in node.exabgp.address_families:
        ${af.name} unicast;
    %endfor
    }

    announce {
        %for af in node.exabgp.address_families:
        ${af.name} {
            %for route in af.routes:
            ${route};
            %endfor
        }
        %endfor
    }
}

%endfor