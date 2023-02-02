import ipaddress

from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class ConcatFeaturesDecimal(BuildingBlock):

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
        source_port = self._convert_decimal_to_dec(networkpacket.source_port())
        destination_port = self._convert_decimal_to_dec(networkpacket.destination_port())
        length = self._convert_decimal_to_dec(networkpacket.length())
        transport_layer_checksum = self._convert_hex_to_dec(networkpacket.transport_layer_checksum())
        # transport_layer_checksum_status = format(networkpacket.transport_layer_checksum_status(), "b")
        transport_layer_flags = self._convert_transport_layer_flags(networkpacket.transport_layer_flags())

        # source_ip_address + destination_ip_address
        concatFeatures = internet_layer_protocol + transport_layer_protocol + source_port + destination_port + length + transport_layer_checksum + transport_layer_flags

        #[int(x) for a, x in enumerate(str(concatFeatures))]
        return [0, 1, 0, 1, 0, 1]

    def depends_on(self):
        return []

    def _convert_internet_layer_protocol(self, internet_layer_protocol) -> float:
        if internet_layer_protocol == "ipv6":
            x = 0.25
        elif internet_layer_protocol == "ipv4":
            x = 0.50
        elif internet_layer_protocol == "ipv4 (arp)":
            x = 0.75
        else:
            x = 0.00
        return float(x)

    def _convert_transport_layer_protocol(self, transport_layer_protocol) -> float:
        if transport_layer_protocol == "tcp":
            x = 0.25
        elif transport_layer_protocol == "udp":
            x = 0.75
        else:
            x = 0.00
        return float(x)

    def _convert_ip_address(self, ip_address, internet_layer_protocol) -> str:
        if internet_layer_protocol == "ipv4":
            y = int(ipaddress.IPv4Address(ip_address))
            ip = format(ipaddress.IPv4Address(ip_address))
            ip_splited = ip.split('.')
            x = ""
            for part in ip_splited:
                y = str(format(int(part), "b")).zfill(8)
                x = x + y
            x = str(x).zfill(128)
        elif internet_layer_protocol == "ipv6":
            y = int(ipaddress.IPv6Address(ip_address))
            ip = ipaddress.IPv6Address(ip_address).exploded
            ip_splited = ip.split(':')
            x = ""
            for part in ip_splited:
                y = str(format(int(part, 16), "b")).zfill(16)
                x = x + y
        else:
            x = str(0).zfill(128)
        return x

    def _convert_transport_layer_flags(self, transport_layer_flags) -> float:
        if transport_layer_flags is None:
            x = 0.0
        else:
            x = ""
            for y in transport_layer_flags:
                x = x + str(y)
            x = int(x) / 1000000
        return float(x)

    def _convert_decimal_to_dec(self, decimal) -> float:
        if decimal is None:
            x = 0.0
        else:
            x = int(decimal) / 100000
        return float(x)

    def _convert_hex_to_dec(self, hex) -> float:
        if hex is None:
            x = 0.0
        else:
            x = int(hex, 16) / 100000
        return float(x)