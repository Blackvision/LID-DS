import ipaddress

from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class ConcatFeatures(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate concatenated features of networkpacket
        """
        if networkpacket.internet_layer_protocol() == 'ipv4':
            source_ip_address = int(ipaddress.IPv4Address(networkpacket.source_ip_address()))
            source_ip_address = str(source_ip_address).zfill(39)
            destination_ip_address = int(ipaddress.IPv4Address(networkpacket.destination_ip_address()))
            destination_ip_address = str(destination_ip_address).zfill(39)

        elif networkpacket.internet_layer_protocol() == 'ipv6':
            source_ip_address = int(ipaddress.IPv6Address(networkpacket.source_ip_address()))
            source_ip_address = str(source_ip_address).zfill(39)
            destination_ip_address = int(ipaddress.IPv6Address(networkpacket.destination_ip_address()))
            destination_ip_address = str(destination_ip_address).zfill(39)
        else:
            source_ip_address = str(0).zfill(39)
            destination_ip_address = str(0).zfill(39)

        if networkpacket.source_port() is not None:
            source_port = str(networkpacket.source_port())
        else:
            source_port = str(0).zfill(4)

        if networkpacket.destination_port() is not None:
            destination_port = str(networkpacket.destination_port())
        else:
            destination_port = str(0).zfill(4)

        concatFeatures = source_ip_address + destination_ip_address + source_port + destination_port

        return concatFeatures

    def depends_on(self):
        return []