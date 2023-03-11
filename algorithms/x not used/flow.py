from numpy import std

from dataloader.networkpacket import Networkpacket


class Flow:

    def __init__(self, init_packet: Networkpacket, connection_id):
        self.init_time = init_packet.timestamp_unix_in_ns()
        self.init_source_ip = init_packet.source_ip_address()
        self.init_destination_ip = init_packet.destination_ip_address()
        self.init_source_port = init_packet.source_port()
        self.init_destination_port = init_packet.destination_port()
        self.flow = []
        self.connection_id = connection_id
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.total_packet_count = 0
        self.total_fwd_packet_count = 0
        self.total_bwd_packet_count = 0
        self.length = []
        self.length_max = 0
        self.length_min = 99999
        self.length_avg = 0
        self.length_std = 0
        self.length_fwd = []
        self.length_max_fwd = 0
        self.length_min_fwd = 99999
        self.length_avg_fwd = 0
        self.length_std_fwd = 0
        self.length_bwd = []
        self.length_max_bwd = 0
        self.length_min_bwd = 99999
        self.length_avg_bwd = 0
        self.length_std_bwd = 0
        self.packets_per_s = 0
        self.bytes_per_s = 0
        self.time_between_two_packets = []
        self.avg_time_between_two_packets = 0
        self.std_time_between_two_packets = 0
        self.data_bytes = []
        self.data_bytes_s_to_d = []
        self.data_bytes_d_to_s = []
        self.add_packet(init_packet)
        # protocols
        # features Fwd/Bwd: packets_per_s, bytes_per_s, avg_time_between_two_packets, std_time_between_two_packets

    def add_packet(self, networkpacket: Networkpacket):
        self.flow.append(networkpacket)
        # self._flag_count(networkpacket)
        # self._packet_count(networkpacket)
        # self._length_calculation(networkpacket)
        # self._packets_bytes_per_s(networkpacket)
        # self._time_between_packets(networkpacket)
        # self._data_bytes_count(networkpacket)

    def belongs_to_flow(self, networkpacket: Networkpacket):
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

    def _flag_count(self, networkpacket: Networkpacket):
        if networkpacket.transport_layer_protocol() == "tcp":
            self.fin_flag_count += networkpacket.tcp_fin_flag()
            self.syn_flag_count += networkpacket.tcp_syn_flag()
            self.rst_flag_count += networkpacket.tcp_rst_flag()
            self.psh_flag_count += networkpacket.tcp_psh_flag()
            self.ack_flag_count += networkpacket.tcp_ack_flag()
            self.urg_flag_count += networkpacket.tcp_urg_flag()

    def _packet_count(self, networkpacket: Networkpacket):
        self.total_packet_count += 1
        if networkpacket.source_ip_address() == self.init_source_ip:
            self.total_fwd_packet_count += 1
        elif networkpacket.source_ip_address() == self.init_destination_ip:
            self.total_bwd_packet_count += 1

    def _length_calculation(self, networkpacket: Networkpacket):
        self.length.append(networkpacket.length())
        if networkpacket.length() > self.length_max:
            self.length_max = networkpacket.length()
        if networkpacket.length() < self.length_min:
            self.length_min = networkpacket.length()
        self.length_avg = round(sum(self.length) / len(self.length), 4)
        self.length_std = round(std(self.length), 4)
        if networkpacket.source_ip_address() == self.init_source_ip:
            self.length_fwd.append(networkpacket.length())
            if networkpacket.length() > self.length_max_fwd:
                self.length_max_fwd = networkpacket.length()
            if networkpacket.length() < self.length_min_fwd:
                self.length_min_fwd = networkpacket.length()
            self.length_avg_fwd = round(sum(self.length_fwd) / len(self.length_fwd), 4)
            self.length_std_fwd = round(std(self.length_fwd), 4)
        elif networkpacket.source_ip_address() == self.init_destination_ip:
            self.length_bwd.append(networkpacket.length())
            if networkpacket.length() > self.length_max_bwd:
                self.length_max_bwd = networkpacket.length()
            if networkpacket.length() < self.length_min_bwd:
                self.length_min_bwd = networkpacket.length()
            self.length_avg_bwd = round(sum(self.length_bwd) / len(self.length_bwd), 4)
            self.length_std_bwd = round(std(self.length_bwd), 4)

    def _packets_bytes_per_s(self, networkpacket: Networkpacket):
        time_window = networkpacket.timestamp_unix_in_ns() - self.init_time
        if time_window > 0:
            time_window_in_s = float(time_window) * float(0.000000001)
            self.packets_per_s = round(self.total_packet_count / time_window_in_s, 4)
            self.bytes_per_s = round(sum(self.length) / time_window_in_s, 4)

    def _time_between_packets(self, networkpacket: Networkpacket):
        if len(self.flow) > 1:
            self.time_between_two_packets.append(
                networkpacket.timestamp_unix_in_ns() - self.flow[-2].timestamp_unix_in_ns())
            self.avg_time_between_two_packets = round(
                sum(self.time_between_two_packets) / len(self.time_between_two_packets))
            self.std_time_between_two_packets = round(std(self.time_between_two_packets))

    def _data_bytes_count(self, networkpacket: Networkpacket):
        if networkpacket.data():
            self.data_bytes.append(networkpacket.data_length())
            if networkpacket.source_ip_address() == self.init_source_ip:
                self.data_bytes_s_to_d.append(networkpacket.data_length())
            elif networkpacket.source_ip_address() == self.init_destination_ip:
                self.data_bytes_d_to_s.append(networkpacket.data_length())
