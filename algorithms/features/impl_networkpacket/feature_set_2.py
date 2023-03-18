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


class FeatureSetTwo(FeatureSet):

    def __init__(self):
        super().__init__()
        self._connections = []
        self.host_ip = None
        self.init_time = 0
        self.packets_bytes_per_s_in = None
        self.packets_bytes_per_s_out = None
        self.time_between_packets_in = TimeBetweenPackets()
        self.time_between_packets_out = TimeBetweenPackets()
        self.length_in = PacketLength()
        self.length_out = PacketLength()
        self.length_udp = PacketLength()
        self.length_tcp = PacketLength()
        self.length_other = PacketLength()
        self.data_bytes_in = DataBytes()
        self.data_bytes_out = DataBytes()
        self.tcp_flag_count_in = FlagCount()
        self.tcp_flag_count_out = FlagCount()
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
            self.packets_bytes_per_s_in = PacketsBytesPerS(self.init_time)
            self.packets_bytes_per_s_out = PacketsBytesPerS(self.init_time)
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
        value.append(self.packets_bytes_per_s_in.bytes_per_s)
        value.append(self.packets_bytes_per_s_in.packets_per_s)
        value.append(self.packets_bytes_per_s_out.bytes_per_s)
        value.append(self.packets_bytes_per_s_out.packets_per_s)
        value.append(self.time_between_packets_in.avg_time_between_two_packets)
        value.append(self.time_between_packets_out.avg_time_between_two_packets)
        value.append(self.length_in.length_min)
        value.append(self.length_in.length_max)
        value.append(self.length_in.length_avg)
        value.append(self.length_out.length_min)
        value.append(self.length_out.length_max)
        value.append(self.length_out.length_avg)
        value.append(self.length_udp.length_min)
        value.append(self.length_udp.length_max)
        value.append(self.length_udp.length_avg)
        value.append(self.length_tcp.length_min)
        value.append(self.length_tcp.length_max)
        value.append(self.length_tcp.length_avg)
        value.append(self.length_other.length_min)
        value.append(self.length_other.length_max)
        value.append(self.length_other.length_avg)
        value.append(self.data_bytes_in.data_bytes_min)
        value.append(self.data_bytes_in.data_bytes_max)
        value.append(self.data_bytes_in.data_bytes_avg)
        value.append(self.data_bytes_out.data_bytes_min)
        value.append(self.data_bytes_out.data_bytes_max)
        value.append(self.data_bytes_out.data_bytes_avg)
        value.append(self.tcp_flag_count_in.fin_flag_perc)
        value.append(self.tcp_flag_count_in.syn_flag_perc)
        value.append(self.tcp_flag_count_in.rst_flag_perc)
        value.append(self.tcp_flag_count_in.psh_flag_perc)
        value.append(self.tcp_flag_count_in.ack_flag_perc)
        value.append(self.tcp_flag_count_in.urg_flag_perc)
        value.append(self.tcp_flag_count_out.fin_flag_perc)
        value.append(self.tcp_flag_count_out.syn_flag_perc)
        value.append(self.tcp_flag_count_out.rst_flag_perc)
        value.append(self.tcp_flag_count_out.psh_flag_perc)
        value.append(self.tcp_flag_count_out.ack_flag_perc)
        value.append(self.tcp_flag_count_out.urg_flag_perc)
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
        if networkpacket.destination_ip_address() == self.host_ip:
            self.packets_bytes_per_s_in.update(networkpacket)
            self.time_between_packets_in.update(networkpacket)
            self.length_in.update(networkpacket)
            self.data_bytes_in.update(networkpacket)
            self.tcp_flag_count_in.update(networkpacket)
        elif networkpacket.source_ip_address() == self.host_ip:
            self.packets_bytes_per_s_out.update(networkpacket)
            self.time_between_packets_out.update(networkpacket)
            self.length_out.update(networkpacket)
            self.data_bytes_out.update(networkpacket)
            self.tcp_flag_count_out.update(networkpacket)

    def depends_on(self):
        return []

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._connections = []
        self.host_ip = None
        self.init_time = 0
        self.packets_bytes_per_s_in = None
        self.packets_bytes_per_s_out = None
        self.time_between_packets_in = TimeBetweenPackets()
        self.time_between_packets_out = TimeBetweenPackets()
        self.length_in = PacketLength()
        self.length_out = PacketLength()
        self.length_udp = PacketLength()
        self.length_tcp = PacketLength()
        self.length_other = PacketLength()
        self.data_bytes_in = DataBytes()
        self.data_bytes_out = DataBytes()
        self.tcp_flag_count_in = FlagCount()
        self.tcp_flag_count_out = FlagCount()
        self.perc_internet_layer = PercInternetLayer()
        self.perc_transport_layer = PercTransportLayer()
        self.connection_packets = ConnectionPackets()
        self.connections_same_host = None
