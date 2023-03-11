from algorithms.features.impl_networkpacket.connection import Connection
from algorithms.features.impl_networkpacket.connection_packets import ConnectionPackets
from algorithms.features.impl_networkpacket.connections_to_same_host import ConnectionsToSameHost
from algorithms.features.impl_networkpacket.data_bytes import DataBytes
from algorithms.features.impl_networkpacket.feature_set import FeatureSet
from algorithms.features.impl_networkpacket.flag_count import FlagCount
from algorithms.features.impl_networkpacket.packet_length import PacketLength
from algorithms.features.impl_networkpacket.packets_bytes_per_s import PacketsBytesPerS
from algorithms.features.impl_networkpacket.perc_internet_layer import PercInternetLayer
from algorithms.features.impl_networkpacket.perc_transport_layer import PercTransportLayer
from algorithms.features.impl_networkpacket.time_between_packets import TimeBetweenPackets
from dataloader.networkpacket import Networkpacket


class FeatureSetOne(FeatureSet):

    def __init__(self):
        super().__init__()
        self._connections = []
        self.host_ip = None
        self.init_time = 0
        self.packets_bytes_per_s = None
        self.time_between_packets = TimeBetweenPackets()
        self.length = PacketLength()
        self.length_udp = PacketLength()
        self.length_tcp = PacketLength()
        self.length_other = PacketLength()
        self.data_bytes = DataBytes()
        self.tcp_flag_count = FlagCount()
        self.perc_internet_layer = PercInternetLayer()
        self.perc_transport_layer = PercTransportLayer()
        self.connection_packets = ConnectionPackets()
        self.connections_same_host = None

    def set_host_ip(self, host_ip):
        if not self.host_ip:
            self.host_ip = host_ip

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate concatenated features of networkpacket
        """
        if not self._connections:
            if not self.host_ip:
                raise Exception('host ip must be set')
            self.init_time = networkpacket.timestamp_unix_in_ns()
            self.packets_bytes_per_s = PacketsBytesPerS(self.init_time)
            self.connections_same_host = ConnectionsToSameHost(self.host_ip)
            self.connections_append(networkpacket)
        else:
            was_added = False
            for connection in self._connections:
                if connection.belongs_to_connection(networkpacket):
                    connection.add_packet(networkpacket)
                    was_added = True
            if not was_added:
                self.connections_append(networkpacket)
        self.connection_features(networkpacket)
        value = []
        value.append(self.packets_bytes_per_s.bytes_per_s)
        value.append(self.packets_bytes_per_s.packets_per_s)
        value.append(self.time_between_packets.avg_time_between_two_packets)
        value.append(self.length.length_min)
        value.append(self.length.length_max)
        value.append(self.length.length_avg)
        value.append(self.length_udp.length_min)
        value.append(self.length_udp.length_max)
        value.append(self.length_udp.length_avg)
        value.append(self.length_tcp.length_min)
        value.append(self.length_tcp.length_max)
        value.append(self.length_tcp.length_avg)
        value.append(self.length_other.length_min)
        value.append(self.length_other.length_max)
        value.append(self.length_other.length_avg)
        value.append(self.data_bytes.data_bytes_min)
        value.append(self.data_bytes.data_bytes_max)
        value.append(self.data_bytes.data_bytes_avg)
        value.append(self.tcp_flag_count.fin_flag_perc)
        value.append(self.tcp_flag_count.syn_flag_perc)
        value.append(self.tcp_flag_count.rst_flag_perc)
        value.append(self.tcp_flag_count.psh_flag_perc)
        value.append(self.tcp_flag_count.ack_flag_perc)
        value.append(self.tcp_flag_count.urg_flag_perc)
        value.append(self.perc_internet_layer.ipv4_packets_perc)
        value.append(self.perc_internet_layer.ipv6_packets_perc)
        value.append(self.perc_internet_layer.other_packets_perc)
        value.append(self.perc_transport_layer.udb_packets_perc)
        value.append(self.perc_transport_layer.tcp_packets_perc)
        value.append(self.perc_transport_layer.other_packets_perc)
        value.append(self.connection_packets.max_num_of_con_same_host)
        value.append(self.connection_packets.avg_packets_in_con)
        value.append(self.connections_same_host.min_num_of_con_same_host)
        value.append(self.connections_same_host.max_num_of_con_same_host)
        value.append(self.connections_same_host.avg_num_of_con_same_host)
        value.append(networkpacket.timestamp_unix_in_ns() - self.init_time)
        return value

    def connections_append(self, networkpacket: Networkpacket):
        connection = Connection(networkpacket)
        self._connections.append(connection)
        self.connections_same_host.update(networkpacket)

    def connection_features(self, networkpacket: Networkpacket):
        self.packets_bytes_per_s.update(networkpacket)
        self.time_between_packets.update(networkpacket)
        self.length.update(networkpacket)
        self.data_bytes.update(networkpacket)
        self.tcp_flag_count.update(networkpacket)
        self.perc_internet_layer.update(networkpacket)
        self.perc_transport_layer.update(networkpacket)
        self.connection_packets.update(self._connections)
        if networkpacket.transport_layer_protocol():
            if networkpacket.transport_layer_protocol() == "udp":
                self.length_udp.update(networkpacket)
            elif networkpacket.transport_layer_protocol() == "tcp":
                self.length_tcp.update(networkpacket)
            else:
                self.length_other.update(networkpacket)

    def depends_on(self):
        return []

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._connections = []
        self.host_ip = None
        self.init_time = 0
        self.packets_bytes_per_s = None
        self.time_between_packets = TimeBetweenPackets()
        self.length = PacketLength()
        self.length_udp = PacketLength()
        self.length_tcp = PacketLength()
        self.length_other = PacketLength()
        self.data_bytes = DataBytes()
        self.tcp_flag_count = FlagCount()
        self.perc_internet_layer = PercInternetLayer()
        self.perc_transport_layer = PercTransportLayer()
        self.connection_packets = ConnectionPackets()
        self.connections_same_host = None
