from algorithms.features.impl_networkpacket.connection import Connection
from algorithms.features.impl_networkpacket.connection_packets import ConnectionPackets
from algorithms.features.impl_networkpacket.connections_to_same_host import ConnectionsToSameHost
from algorithms.features.impl_networkpacket.feature_set import FeatureSet
from dataloader.networkpacket import Networkpacket


class CountTimeWindow:

    def __init__(self):
        # 2s   in ns (2000000000)
        # 1,5s in ns (1500000000)
        # 1s   in ns (1000000000)
        self._time_window = 1500000000
        self._values = []
        self.value_list = []

    def add_to(self, time_stamp, value):
        self._values.append((time_stamp, value))
        while self._values[0][0] < (time_stamp - self._time_window):
            self._values.remove(self._values[0])
        self.value_list = []
        for value in self._values:
            self.value_list.append(value[1])


class FlagCount:

    def __init__(self):
        self.tcp_packet_count = 0
        self._fin_flag = CountTimeWindow()
        self._syn_flag = CountTimeWindow()
        self._rst_flag = CountTimeWindow()
        self._psh_flag = CountTimeWindow()
        self._ack_flag = CountTimeWindow()
        self._urg_flag = CountTimeWindow()
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.fin_flag_perc = 0
        self.syn_flag_perc = 0
        self.rst_flag_perc = 0
        self.psh_flag_perc = 0
        self.ack_flag_perc = 0
        self.urg_flag_perc = 0

    def update(self, networkpacket: Networkpacket):
        if networkpacket.transport_layer_protocol() == "tcp":
            self.tcp_packet_count += 1
            self._fin_flag.add_to(networkpacket.timestamp_unix_in_ns(), networkpacket.tcp_fin_flag())
            self._syn_flag.add_to(networkpacket.timestamp_unix_in_ns(), networkpacket.tcp_syn_flag())
            self._rst_flag.add_to(networkpacket.timestamp_unix_in_ns(), networkpacket.tcp_rst_flag())
            self._psh_flag.add_to(networkpacket.timestamp_unix_in_ns(), networkpacket.tcp_psh_flag())
            self._ack_flag.add_to(networkpacket.timestamp_unix_in_ns(), networkpacket.tcp_ack_flag())
            self._urg_flag.add_to(networkpacket.timestamp_unix_in_ns(), networkpacket.tcp_urg_flag())
            self.fin_flag_count = sum(self._fin_flag.value_list)
            self.syn_flag_count = sum(self._syn_flag.value_list)
            self.rst_flag_count = sum(self._rst_flag.value_list)
            self.psh_flag_count = sum(self._psh_flag.value_list)
            self.ack_flag_count = sum(self._ack_flag.value_list)
            self.urg_flag_count = sum(self._urg_flag.value_list)
            self.fin_flag_perc = self.fin_flag_count / self.tcp_packet_count
            self.syn_flag_perc = self.syn_flag_count / self.tcp_packet_count
            self.rst_flag_perc = self.rst_flag_count / self.tcp_packet_count
            self.psh_flag_perc = self.psh_flag_count / self.tcp_packet_count
            self.ack_flag_perc = self.ack_flag_count / self.tcp_packet_count
            self.urg_flag_perc = self.urg_flag_count / self.tcp_packet_count


class Length:

    def __init__(self):
        self._length = CountTimeWindow()
        self.length_max = 0
        self.length_min = 0
        self.length_avg = 0

    def update(self, networkpacket: Networkpacket):
        self._length.add_to(networkpacket.timestamp_unix_in_ns(), int(networkpacket.length()))
        self.length_max = max(self._length.value_list)
        self.length_min = min(self._length.value_list)
        self.length_avg = round(sum(self._length.value_list) / len(self._length.value_list), 4)


class DataBytes:

    def __init__(self):
        self._data_bytes = CountTimeWindow()
        self.data_bytes_max = 0
        self.data_bytes_min = 0
        self.data_bytes_avg = 0

    def update(self, networkpacket: Networkpacket):
        if networkpacket.data_length():
            self._data_bytes.add_to(networkpacket.timestamp_unix_in_ns(), int(networkpacket.data_length()))
            self.data_bytes_max = max(self._data_bytes.value_list)
            self.data_bytes_min = min(self._data_bytes.value_list)
            self.data_bytes_avg = round(sum(self._data_bytes.value_list) / len(self._data_bytes.value_list), 4)


class PacketsBytesPerS:

    def __init__(self, init_time):
        self._init_time = init_time
        self._length = CountTimeWindow()
        self.total_packet_count = 0
        self.packets_per_s = 0
        self.bytes_per_s = 0

    def update(self, networkpacket: Networkpacket):
        self._length.add_to(networkpacket.timestamp_unix_in_ns(), int(networkpacket.length()))
        if networkpacket.timestamp_unix_in_ns() > self._init_time:
            if networkpacket.timestamp_unix_in_ns() - self._init_time < 1500000000:
                time_window_in_s = float(networkpacket.timestamp_unix_in_ns() - self._init_time) * float(0.000000001)
            else:
                time_window_in_s = float(1500000000) * float(0.000000001)
            self.total_packet_count = len(self._length.value_list)
            self.packets_per_s = round(self.total_packet_count / time_window_in_s, 4)
            self.bytes_per_s = round(sum(self._length.value_list) / time_window_in_s, 4)


class TimeBetweenPackets:

    def __init__(self):
        self._last_packet_time_stamp = None
        self._time_between_packets = CountTimeWindow()
        self.avg_time_between_two_packets = 0

    def update(self, networkpacket: Networkpacket):
        if self._last_packet_time_stamp:
            self._time_between_packets.add_to(networkpacket.timestamp_unix_in_ns(),
                                              int(networkpacket.timestamp_unix_in_ns() - self._last_packet_time_stamp))
            self.avg_time_between_two_packets = round(sum(self._time_between_packets.value_list) /
                                                      len(self._time_between_packets.value_list), 4)
        self._last_packet_time_stamp = networkpacket.timestamp_unix_in_ns()


class PercInternetLayer:

    def __init__(self):
        self._total_packet_count = 0
        self._ipv4_packets = CountTimeWindow()
        self._ipv6_packets = CountTimeWindow()
        self._other_packets = CountTimeWindow()
        self.ipv4_packets_perc = 0
        self.ipv6_packets_perc = 0
        self.other_packets_perc = 0

    def update(self, networkpacket: Networkpacket):
        self._total_packet_count += 1
        if networkpacket.internet_layer_protocol() == "ipv4":
            self._ipv4_packets.add_to(networkpacket.timestamp_unix_in_ns(), 1)
        elif networkpacket.internet_layer_protocol() == "ipv6":
            self._ipv6_packets.add_to(networkpacket.timestamp_unix_in_ns(), 1)
        else:
            self._other_packets.add_to(networkpacket.timestamp_unix_in_ns(), 1)
        self.ipv4_packets_perc = sum(self._ipv4_packets.value_list) / self._total_packet_count
        self.ipv6_packets_perc = sum(self._ipv6_packets.value_list) / self._total_packet_count
        self.other_packets_perc = sum(self._other_packets.value_list) / self._total_packet_count


class PercTransportLayer:

    def __init__(self):
        self._total_packet_count = 0
        self._udp_packets = CountTimeWindow()
        self._tcp_packets = CountTimeWindow()
        self._other_packets = CountTimeWindow()
        self.udb_packets_perc = 0
        self.tcp_packets_perc = 0
        self.other_packets_perc = 0

    def update(self, networkpacket: Networkpacket):
        self._total_packet_count += 1
        if networkpacket.transport_layer_protocol():
            if networkpacket.transport_layer_protocol() == "udp":
                self._udp_packets.add_to(networkpacket.timestamp_unix_in_ns(), 1)
            elif networkpacket.transport_layer_protocol() == "tcp":
                self._tcp_packets.add_to(networkpacket.timestamp_unix_in_ns(), 1)
            else:
                self._other_packets.add_to(networkpacket.timestamp_unix_in_ns(), 1)
            self.udb_packets_perc = sum(self._udp_packets.value_list) / self._total_packet_count
            self.tcp_packets_perc = sum(self._tcp_packets.value_list) / self._total_packet_count
            self.other_packets_perc = sum(self._other_packets.value_list) / self._total_packet_count


class FeatureSetFive(FeatureSet):

    def __init__(self):
        super().__init__()
        self._connections = []
        self.host_ip = None
        self.init_time = 0
        self.packets_bytes_per_s = None
        self.time_between_packets = TimeBetweenPackets()
        self.length = Length()
        self.length_udp = Length()
        self.length_tcp = Length()
        self.length_other = Length()
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
        self.length = Length()
        self.length_udp = Length()
        self.length_tcp = Length()
        self.length_other = Length()
        self.data_bytes = DataBytes()
        self.tcp_flag_count = FlagCount()
        self.perc_internet_layer = PercInternetLayer()
        self.perc_transport_layer = PercTransportLayer()
        self.connection_packets = ConnectionPackets()
        self.connections_same_host = None
