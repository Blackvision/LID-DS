from dataloader.networkpacket import Networkpacket


class PercTransportLayer:

    def __init__(self):
        self._total_packet_count = 0
        self._udp_packets = 0
        self._tcp_packets = 0
        self._other_packets = 0
        self.udb_packets_perc = 0
        self.tcp_packets_perc = 0
        self.other_packets_perc = 0

    def update(self, networkpacket: Networkpacket):
        self._total_packet_count += 1
        if networkpacket.transport_layer_protocol():
            if networkpacket.transport_layer_protocol() == "udp":
                self._udp_packets += 1
            elif networkpacket.transport_layer_protocol() == "tcp":
                self._tcp_packets += 1
            else:
                self._other_packets += 1
            self.udb_packets_perc = self._udp_packets / self._total_packet_count
            self.tcp_packets_perc = self._tcp_packets / self._total_packet_count
            self.other_packets_perc = self._other_packets / self._total_packet_count
