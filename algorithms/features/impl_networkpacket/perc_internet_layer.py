from dataloader.networkpacket import Networkpacket


class PercInternetLayer:

    def __init__(self):
        self._total_packet_count = 0
        self._ipv4_packets = 0
        self._ipv6_packets = 0
        self._other_packets = 0
        self.ipv4_packets_perc = 0
        self.ipv6_packets_perc = 0
        self.other_packets_perc = 0

    def update(self, networkpacket: Networkpacket):
        self._total_packet_count += 1
        if networkpacket.internet_layer_protocol() == "ipv4":
            self._ipv4_packets += 1
        elif networkpacket.internet_layer_protocol() == "ipv6":
            self._ipv6_packets += 1
        else:
            self._other_packets += 1
        self.ipv4_packets_perc = self._ipv4_packets / self._total_packet_count
        self.ipv6_packets_perc = self._ipv6_packets / self._total_packet_count
        self.other_packets_perc = self._other_packets / self._total_packet_count
