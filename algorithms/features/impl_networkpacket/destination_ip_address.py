import ipaddress

from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class DestinationIpAddress(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate destination ip adresses of networkpacket
        """
        if networkpacket.internet_layer_protocol() == 'ipv4':
            destination_ip_address = str(int(ipaddress.IPv4Address(networkpacket.destination_ip_address()))).zfill(39)
        elif networkpacket.internet_layer_protocol() == 'ipv6':
            destination_ip_address = str(int(ipaddress.IPv6Address(networkpacket.destination_ip_address()))).zfill(39)
        else:
            destination_ip_address = str(0).zfill(39)
        return destination_ip_address

    def depends_on(self):
        return []
