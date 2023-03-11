from algorithms.features.impl_networkpacket.feature_set import FeatureSet
from dataloader.networkpacket import Networkpacket


class FlagCount:

    def __init__(self):
        self.tcp_packet_count = 0
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
            self.fin_flag_count += networkpacket.tcp_fin_flag()
            self.syn_flag_count += networkpacket.tcp_syn_flag()
            self.rst_flag_count += networkpacket.tcp_rst_flag()
            self.psh_flag_count += networkpacket.tcp_psh_flag()
            self.ack_flag_count += networkpacket.tcp_ack_flag()
            self.urg_flag_count += networkpacket.tcp_urg_flag()
            self.fin_flag_perc = self.fin_flag_count / self.tcp_packet_count
            self.syn_flag_perc = self.syn_flag_count / self.tcp_packet_count
            self.rst_flag_perc = self.rst_flag_count / self.tcp_packet_count
            self.psh_flag_perc = self.psh_flag_count / self.tcp_packet_count
            self.ack_flag_perc = self.ack_flag_count / self.tcp_packet_count
            self.urg_flag_perc = self.urg_flag_count / self.tcp_packet_count


class Length:

    def __init__(self):
        self._length = []
        self.length_max = 0
        self.length_min = 0
        self.length_avg = 0
        # self.length_std = 0

    def update(self, networkpacket: Networkpacket):
        if len(self._length) <= 0:
            self.length_max = networkpacket.length()
            self.length_min = networkpacket.length()
        self._length.append(networkpacket.length())
        if networkpacket.length() > self.length_max:
            self.length_max = networkpacket.length()
        if networkpacket.length() < self.length_min:
            self.length_min = networkpacket.length()
        self.length_avg = round(sum(self._length) / len(self._length), 4)
        # self.length_std = round(std(self._length), 4)


class DataBytes:

    def __init__(self):
        self._data_bytes = []
        self.data_bytes_max = 0
        self.data_bytes_min = 0
        self.data_bytes_avg = 0
        # self.data_bytes_std = 0

    def update(self, networkpacket: Networkpacket):
        if networkpacket.data_length():
            if len(self._data_bytes) <= 0:
                self.data_bytes_max = networkpacket.data_length()
                self.data_bytes_min = networkpacket.data_length()
            self._data_bytes.append(int(networkpacket.data_length()))
            if networkpacket.data_length() > self.data_bytes_max:
                self.data_bytes_max = networkpacket.data_length()
            if networkpacket.data_length() < self.data_bytes_min:
                self.data_bytes_min = networkpacket.data_length()
            self.data_bytes_avg = round(sum(self._data_bytes) / len(self._data_bytes), 4)
            # self.data_bytes_std = round(std(self._data_bytes), 4)


class PacketsBytesPerS:

    def __init__(self, init_time):
        self._init_time = init_time
        self._length = []
        self.total_packet_count = 0
        self.packets_per_s = 0
        self.bytes_per_s = 0

    def update(self, networkpacket: Networkpacket):
        self.total_packet_count += 1
        self._length.append(networkpacket.length())
        time_window_recording = networkpacket.timestamp_unix_in_ns() - self._init_time
        if time_window_recording > 0:
            time_window_in_s = float(time_window_recording) * float(0.000000001)
            self.packets_per_s = round(self.total_packet_count / time_window_in_s, 4)
            self.bytes_per_s = round(sum(self._length) / time_window_in_s, 4)


class TimeBetweenPackets:

    def __init__(self):
        self._last_packet_time_stamp = None
        self._time_between_packets = []
        self.avg_time_between_two_packets = 0
        # self.std_time_between_two_packets = 0

    def update(self, networkpacket: Networkpacket):
        if self._last_packet_time_stamp:
            self._time_between_packets.append(networkpacket.timestamp_unix_in_ns() - self._last_packet_time_stamp)
            self.avg_time_between_two_packets = round(sum(self._time_between_packets) / len(self._time_between_packets))
            # self.std_time_between_two_packets = round(std(self._time_between_packets))
        self._last_packet_time_stamp = networkpacket.timestamp_unix_in_ns()


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


class ConnectionPackets:

    def __init__(self):
        self.max_num_of_con_same_host = 0
        self.avg_packets_in_con = 0
        # self.std_packets_in_con = 0

    def update(self, connections):
        packets_in_connection = []
        for connection in connections:
            packets_in_connection.append(len(connection.connection_packets))
            if len(connection.connection_packets) > self.max_num_of_con_same_host:
                self.max_num_of_con_same_host = len(connection.connection_packets)
        if packets_in_connection:
            self.avg_packets_in_con = round(sum(packets_in_connection) / len(packets_in_connection), 4)
            # self.std_packets_in_con = round(std(packets_in_connection), 4)


class ConnectionsSameHost:

    def __init__(self, host_ip):
        self._host_ip = host_ip
        self._num_of_con_same_host = {}
        self.min_num_of_con_same_host = 9999
        self.max_num_of_con_same_host = 0
        self.avg_num_of_con_same_host = 0
        # self.std_num_of_con_same_host = 0

    def update(self, networkpacket: Networkpacket):
        if networkpacket.source_ip_address() == self._host_ip:
            if networkpacket.destination_ip_address() not in self._num_of_con_same_host:
                self._num_of_con_same_host[networkpacket.destination_ip_address()] = 1
            else:
                self._num_of_con_same_host[networkpacket.destination_ip_address()] += 1
            if self._num_of_con_same_host[networkpacket.destination_ip_address()] > self.max_num_of_con_same_host:
                self.max_num_of_con_same_host = self._num_of_con_same_host[networkpacket.destination_ip_address()]
            if self._num_of_con_same_host[networkpacket.destination_ip_address()] < self.min_num_of_con_same_host:
                self.min_num_of_con_same_host = self._num_of_con_same_host[networkpacket.destination_ip_address()]
        elif networkpacket.destination_ip_address() == self._host_ip:
            if networkpacket.source_ip_address() not in self._num_of_con_same_host:
                self._num_of_con_same_host[networkpacket.source_ip_address()] = 1
            else:
                self._num_of_con_same_host[networkpacket.source_ip_address()] += 1
            if self._num_of_con_same_host[networkpacket.source_ip_address()] > self.max_num_of_con_same_host:
                self.max_num_of_con_same_host = self._num_of_con_same_host[networkpacket.source_ip_address()]
            if self._num_of_con_same_host[networkpacket.source_ip_address()] < self.min_num_of_con_same_host:
                self.min_num_of_con_same_host = self._num_of_con_same_host[networkpacket.source_ip_address()]
        # else:
        #     key = networkpacket.source_ip_address() + networkpacket.destination_ip_address()
        #     if key not in self._num_of_con_same_host:
        #         self._num_of_con_same_host[key] = 1
        #     else:
        #         self._num_of_con_same_host[key] += 1
        if len(self._num_of_con_same_host) > 0:
            numbers = []
            for number in self._num_of_con_same_host.values():
                numbers.append(number)
            self.avg_num_of_con_same_host = round(sum(numbers) / len(numbers), 4)
            # self.std_num_of_con_same_host = round(std(numbers), 4)


class Connection:

    def __init__(self, init_packet: Networkpacket):
        self.init_time = init_packet.timestamp_unix_in_ns()
        self.init_source_ip = init_packet.source_ip_address()
        self.init_destination_ip = init_packet.destination_ip_address()
        self.init_source_port = init_packet.source_port()
        self.init_destination_port = init_packet.destination_port()
        self.connection_packets = []
        self.add_packet(init_packet)

    def add_packet(self, networkpacket: Networkpacket):
        self.connection_packets.append(networkpacket)

    def belongs_to_connection(self, networkpacket: Networkpacket):
        if (networkpacket.source_ip_address() == self.init_source_ip and
                networkpacket.source_port() == self.init_source_port and
                networkpacket.destination_ip_address() == self.init_destination_ip and
                networkpacket.destination_port() == self.init_destination_port):
            return True
        elif (networkpacket.source_ip_address() == self.init_destination_ip and
              networkpacket.source_port() == self.init_destination_port and
              networkpacket.destination_ip_address() == self.init_source_ip and
              networkpacket.destination_port() == self.init_source_port):
            return True
        else:
            return False


class FlowFeaturesThree(FeatureSet):

    def __init__(self):
        super().__init__()
        self._connections = []
        self.host_ip = None
        self.init_time = 0
        self.packets_bytes_per_s = None
        self.packets_bytes_per_s_in = None
        self.packets_bytes_per_s_out = None
        self.time_between_packets = TimeBetweenPackets()
        self.time_between_packets_in = TimeBetweenPackets()
        self.time_between_packets_out = TimeBetweenPackets()
        self.length = Length()
        self.length_in = Length()
        self.length_out = Length()
        self.length_udp = Length()
        self.length_tcp = Length()
        self.length_other = Length()
        self.data_bytes = DataBytes()
        self.data_bytes_in = DataBytes()
        self.data_bytes_out = DataBytes()
        self.tcp_flag_count = FlagCount()
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
            self.packets_bytes_per_s = PacketsBytesPerS(self.init_time)
            self.packets_bytes_per_s_in = PacketsBytesPerS(self.init_time)
            self.packets_bytes_per_s_out = PacketsBytesPerS(self.init_time)
            self.connections_same_host = ConnectionsSameHost(self.host_ip)
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
        value.append(self.packets_bytes_per_s_in.bytes_per_s)
        value.append(self.packets_bytes_per_s_in.packets_per_s)
        value.append(self.packets_bytes_per_s_out.bytes_per_s)
        value.append(self.packets_bytes_per_s_out.packets_per_s)
        value.append(self.time_between_packets.avg_time_between_two_packets)
        value.append(self.time_between_packets_in.avg_time_between_two_packets)
        value.append(self.time_between_packets_out.avg_time_between_two_packets)
        # value.append(self.time_between_packets.std_time_between_two_packets)
        value.append(self.length.length_min)
        value.append(self.length.length_max)
        value.append(self.length.length_avg)
        value.append(self.length_in.length_min)
        value.append(self.length_in.length_max)
        value.append(self.length_in.length_avg)
        value.append(self.length_out.length_min)
        value.append(self.length_out.length_max)
        value.append(self.length_out.length_avg)
        # value.append(self.length.length_std)
        value.append(self.length_udp.length_min)
        value.append(self.length_udp.length_max)
        value.append(self.length_udp.length_avg)
        # value.append(self.length_udp.length_std)
        value.append(self.length_tcp.length_min)
        value.append(self.length_tcp.length_max)
        value.append(self.length_tcp.length_avg)
        # value.append(self.length_tcp.length_std)
        value.append(self.length_other.length_min)
        value.append(self.length_other.length_max)
        value.append(self.length_other.length_avg)
        # value.append(self.length_other.length_std)
        value.append(self.data_bytes.data_bytes_min)
        value.append(self.data_bytes.data_bytes_max)
        value.append(self.data_bytes.data_bytes_avg)
        value.append(self.data_bytes_in.data_bytes_min)
        value.append(self.data_bytes_in.data_bytes_max)
        value.append(self.data_bytes_in.data_bytes_avg)
        value.append(self.data_bytes_out.data_bytes_min)
        value.append(self.data_bytes_out.data_bytes_max)
        value.append(self.data_bytes_out.data_bytes_avg)
        # value.append(self.data_bytes.data_bytes_std)
        value.append(self.tcp_flag_count.fin_flag_perc)
        value.append(self.tcp_flag_count.syn_flag_perc)
        value.append(self.tcp_flag_count.rst_flag_perc)
        value.append(self.tcp_flag_count.psh_flag_perc)
        value.append(self.tcp_flag_count.ack_flag_perc)
        value.append(self.tcp_flag_count.urg_flag_perc)
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
        # value.append(self.connection_packets.std_packets_in_con)
        value.append(self.connections_same_host.min_num_of_con_same_host)
        value.append(self.connections_same_host.max_num_of_con_same_host)
        value.append(self.connections_same_host.avg_num_of_con_same_host)
        # value.append(self.connections_same_host.std_num_of_con_same_host)
        value.append(networkpacket.timestamp_unix_in_ns() - self.init_time)
        # self.perc_highest_layer_protocol()
        # (Percentage of connections that were to same/different hosts/ip)
        # (Percentage/Number of connections having the same/different portnumber/protocol)
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
        self.packets_bytes_per_s = None
        self.packets_bytes_per_s_in = None
        self.packets_bytes_per_s_out = None
        self.time_between_packets = TimeBetweenPackets()
        self.time_between_packets_in = TimeBetweenPackets()
        self.time_between_packets_out = TimeBetweenPackets()
        self.length = Length()
        self.length_in = Length()
        self.length_out = Length()
        self.length_udp = Length()
        self.length_tcp = Length()
        self.length_other = Length()
        self.data_bytes = DataBytes()
        self.data_bytes_in = DataBytes()
        self.data_bytes_out = DataBytes()
        self.tcp_flag_count = FlagCount()
        self.tcp_flag_count_in = FlagCount()
        self.tcp_flag_count_out = FlagCount()
        self.perc_internet_layer = PercInternetLayer()
        self.perc_transport_layer = PercTransportLayer()
        self.connection_packets = ConnectionPackets()
        self.connections_same_host = None
