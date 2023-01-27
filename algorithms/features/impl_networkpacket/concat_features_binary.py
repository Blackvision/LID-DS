import ipaddress

from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class ConcatFeaturesBinary(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate concatenated features of networkpacket
        """

        # internet_layer_protocol
        # source_ip_address
        # destination_ip_address
        # transport_layer_protocol
        # source_port
        # destination_port
        # length
        # transport_layer_checksum
        # transport_layer_checksum_status
        # transport_layer_flags
        # data

        internet_layer_protocol = self._convert_internet_layer_protocol(networkpacket.internet_layer_protocol())
        source_ip_address = self._convert_ip_address(networkpacket.source_ip_address(), networkpacket.internet_layer_protocol())
        destination_ip_address = self._convert_ip_address(networkpacket.destination_ip_address(), networkpacket.internet_layer_protocol())
        transport_layer_protocol = self._convert_transport_layer_protocol(networkpacket.transport_layer_protocol())
        source_port = self._convert_decimal_to_16_bit(networkpacket.source_port())
        destination_port = self._convert_decimal_to_16_bit(networkpacket.destination_port())
        length = self._convert_decimal_to_16_bit(networkpacket.length())
        transport_layer_checksum = self._convert_hex_to_16_bit(networkpacket.transport_layer_checksum())
        # transport_layer_checksum_status = format(networkpacket.transport_layer_checksum_status(), "b")
        transport_layer_flags = self._convert_transport_layer_flags(networkpacket.transport_layer_flags())

        concatFeatures = internet_layer_protocol + source_ip_address + destination_ip_address + transport_layer_protocol + source_port + destination_port + length + transport_layer_checksum + transport_layer_flags

        return [int(x) for a, x in enumerate(str(concatFeatures))]

    def depends_on(self):
        return []

    def _convert_internet_layer_protocol(self, internet_layer_protocol) -> str:
        if internet_layer_protocol == "ipv6":
            x = "11"
        elif internet_layer_protocol == "ipv4":
            x = "10"
        elif internet_layer_protocol == "ipv4 (arp)":
            x = "01"
        else:
            x = "00"
        return x

    def _convert_transport_layer_protocol(self, transport_layer_protocol) -> str:
        if transport_layer_protocol == "tcp":
            x = "11"
        elif transport_layer_protocol == "udp":
            x = "10"
        else:
            x = "01"
        return x

    def _convert_ip_address(self, ip_address, internet_layer_protocol) -> str:
        if internet_layer_protocol == "ipv4":
            ip = format(ipaddress.IPv4Address(ip_address))
            ip_splited = ip.split('.')
            x = ""
            for part in ip_splited:
                y = str(format(int(part), "b")).zfill(8)
                x = x + y
            x = str(x).zfill(128)
        elif internet_layer_protocol == "ipv6":
            ip = ipaddress.IPv6Address(ip_address).exploded
            ip_splited = ip.split(':')
            x = ""
            for part in ip_splited:
                y = str(format(int(part, 16), "b")).zfill(16)
                x = x + y
        else:
            x = str(0).zfill(128)
        return x

    def _convert_transport_layer_flags(self, transport_layer_flags) -> str:
        if transport_layer_flags is None:
            return "000000"
        x = ""
        for y in transport_layer_flags:
            x + str(y)
        return x

    def _convert_decimal_to_16_bit(self, decimal) -> str:
        if decimal is None:
            x = str(0).zfill(16)
        else:
            x = str(format(decimal, "b")).zfill(16)
        return x

    def _convert_hex_to_16_bit(self, hex) -> str:
        if hex is None:
            x = str(0).zfill(16)
        else:
            x = str(format(int(hex, 16), "b")).zfill(16)
        return x