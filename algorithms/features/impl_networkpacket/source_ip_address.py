import ipaddress

from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class SourceIpAddress(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate source ip adresses of networkpacket
        """
        if networkpacket.internet_layer_protocol() == 'ipv4':
            source_ip_address = str(int(ipaddress.IPv4Address(networkpacket.source_ip_address()))).zfill(39)
        elif networkpacket.internet_layer_protocol() == 'ipv6':
            source_ip_address = str(int(ipaddress.IPv6Address(networkpacket.source_ip_address()))).zfill(39)
        else:
            source_ip_address = str(0).zfill(39)
        return source_ip_address

    def depends_on(self):
        return []
