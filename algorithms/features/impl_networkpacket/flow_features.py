from numpy import std

from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class Flow:

    def __init__(self, init_packet: Networkpacket):
        self.init_time = init_packet.timestamp_unix_in_ns()
        self.init_source_ip = init_packet.source_ip_address()
        self.init_destination_ip = init_packet.destination_ip_address()
        self.init_source_port = init_packet.source_port()
        self.init_destination_port = init_packet.destination_port()
        self.flow = []
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
        # protocol
        # (Features ein- u. ausgehend zu Host betrachten)

    def add_packet(self, networkpacket: Networkpacket):
        self.flow.append(networkpacket)
        self.flag_count(networkpacket)
        self.packet_count(networkpacket)
        self.length_calculation(networkpacket)
        self.packets_bytes_per_s(networkpacket)
        self.time_between_packets(networkpacket)
        # self.data_bytes_count(networkpacket)

    def flag_count(self, networkpacket: Networkpacket):
        if networkpacket.transport_layer_protocol() == "tcp":
            self.fin_flag_count += networkpacket.tcp_fin_flag()
            self.syn_flag_count += networkpacket.tcp_syn_flag()
            self.rst_flag_count += networkpacket.tcp_rst_flag()
            self.psh_flag_count += networkpacket.tcp_psh_flag()
            self.ack_flag_count += networkpacket.tcp_ack_flag()
            self.urg_flag_count += networkpacket.tcp_urg_flag()

    def packet_count(self, networkpacket: Networkpacket):
        self.total_packet_count += 1
        if networkpacket.source_ip_address() == self.init_source_ip:
            self.total_fwd_packet_count += 1
        elif networkpacket.source_ip_address() == self.init_destination_ip:
            self.total_bwd_packet_count += 1

    def length_calculation(self, networkpacket: Networkpacket):
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

    def packets_bytes_per_s(self, networkpacket: Networkpacket):
        time_window = networkpacket.timestamp_unix_in_ns() - self.init_time
        if time_window > 0:
            time_window_in_s = float(time_window) * float(0.000000001)
            self.packets_per_s = round(self.total_packet_count / time_window_in_s, 4)
            self.bytes_per_s = round(sum(self.length) / time_window_in_s, 4)

    def time_between_packets(self, networkpacket: Networkpacket):
        if len(self.flow) > 1:
            self.time_between_two_packets.append(networkpacket.timestamp_unix_in_ns() - self.flow[-2].timestamp_unix_in_ns())
            self.avg_time_between_two_packets = round(sum(self.time_between_two_packets) / len(self.time_between_two_packets))
            self.std_time_between_two_packets = round(std(self.time_between_two_packets))

    def data_bytes_count(self, networkpacket: Networkpacket):
        if networkpacket.data():
            self.data_bytes.append(networkpacket.data_length())
            if networkpacket.source_ip_address() == self.init_source_ip:
                self.data_bytes_s_to_d.append(networkpacket.data_length())
            elif networkpacket.source_ip_address() == self.init_destination_ip:
                self.data_bytes_d_to_s.append(networkpacket.data_length())

    # kann weg
    def packets_bytes_in_last_s(self, networkpacket: Networkpacket):
        packets = 0
        bytes = 0
        time = networkpacket.timestamp_unix_in_ns() - 1000000000
        for packet in reversed(self.flow):
            if packet.timestamp_unix_in_ns() > time:
                packets = packets + 1
                bytes = bytes + packet.length
            else:
                break

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

class FlowFeatures(BuildingBlock):

    def __init__(self):
        super().__init__()
        self._flows = []
        self.host_ip = None
        self.init_time = 0
        self.flow_count = 0
        self.total_packet_count = 0
        self.total_out_packet_count = 0
        self.total_in_packet_count = 0
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.length = []
        self.length_max = 0
        self.length_min = 99999
        self.length_avg = 0
        self.length_std = 0
        self.length_out = []
        self.length_max_out = 0
        self.length_min_out = 99999
        self.length_avg_out = 0
        self.length_std_out = 0
        self.length_in = []
        self.length_max_in = 0
        self.length_min_in = 99999
        self.length_avg_in = 0
        self.length_std_in = 0
        self.packets_per_s = 0
        self.bytes_per_s = 0
        self.last_packet_time_stamp = None
        self.time_between_two_packets = []
        self.time_window_recording = 0
        self.avg_time_between_two_packets = 0
        self.std_time_between_two_packets = 0
        self.num_of_con_same_host = {}
        self.num_of_con_to_same_host = {}
        self.num_of_con_from_same_host = {}
        self.perc_of_con_same_host = {}
        self.perc_of_con_to_same_host = {}
        self.perc_of_con_from_same_host = {}
        # Features auf protocole bezogen

    def set_host_ip(self, host_ip):
        if not self.host_ip:
            self.host_ip = host_ip

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate concatenated features of networkpacket
        """
        if self._flows:
            was_added = False
            for flow in self._flows:
                if flow.belongs_to_flow(networkpacket):
                    flow.add_packet(networkpacket)
                    was_added = True
            if not was_added:
                self.flows_append(networkpacket)
        else:
            if not self.host_ip:
                raise Exception('host ip must be set')
            self.init_time = networkpacket.timestamp_unix_in_ns()
            self.flows_append(networkpacket)
        self.flow_metrics(networkpacket)
        value = []
        value.append(self.flow_count)
        value.append(self.total_packet_count)
        value.append(self.total_out_packet_count)
        value.append(self.total_in_packet_count)
        value.append(self.fin_flag_count)
        value.append(self.syn_flag_count)
        value.append(self.rst_flag_count)
        value.append(self.psh_flag_count)
        value.append(self.ack_flag_count)
        value.append(self.urg_flag_count)
        value.append(self.length_max)
        value.append(self.length_min)
        value.append(self.length_avg)
        value.append(self.length_std)
        value.append(self.length_max_out)
        value.append(self.length_min_out)
        value.append(self.length_avg_out)
        value.append(self.length_std_out)
        value.append(self.length_max_in)
        value.append(self.length_min_in)
        value.append(self.length_avg_in)
        value.append(self.length_std_in)
        value.append(self.packets_per_s)
        value.append(self.bytes_per_s)
        value.append(self.avg_time_between_two_packets)
        value.append(self.std_time_between_two_packets)
        return value

    def flows_append(self, networkpacket: Networkpacket):
        flow = Flow(networkpacket)
        self._flows.append(flow)
        self.flow_count += 1
        self.num_connections_same_host(networkpacket)
        self.perc_connections_same_host()

    def flow_metrics(self, networkpacket: Networkpacket):
        self.flag_count(networkpacket)
        self.length_calculation(networkpacket)
        self.packet_count(networkpacket)
        self.packets_bytes_per_s(networkpacket)
        self.time_between_packets(networkpacket)

    def flag_count(self, networkpacket: Networkpacket):
        if networkpacket.transport_layer_protocol() == "tcp":
            self.fin_flag_count += networkpacket.tcp_fin_flag()
            self.syn_flag_count += networkpacket.tcp_syn_flag()
            self.rst_flag_count += networkpacket.tcp_rst_flag()
            self.psh_flag_count += networkpacket.tcp_psh_flag()
            self.ack_flag_count += networkpacket.tcp_ack_flag()
            self.urg_flag_count += networkpacket.tcp_urg_flag()

    def length_calculation(self, networkpacket: Networkpacket):
        self.length.append(networkpacket.length())
        if networkpacket.length() > self.length_max:
            self.length_max = networkpacket.length()
        if networkpacket.length() < self.length_min:
            self.length_min = networkpacket.length()
        self.length_avg = round(sum(self.length) / len(self.length), 4)
        self.length_std = round(std(self.length), 4)
        if networkpacket.source_ip_address() == self.host_ip:
            self.length_out.append(networkpacket.length())
            if networkpacket.length() > self.length_max_out:
                self.length_max_out = networkpacket.length()
            if networkpacket.length() < self.length_min_out:
                self.length_min_out = networkpacket.length()
            self.length_avg_out = round(sum(self.length_out) / len(self.length_out), 4)
            self.length_std_out = round(std(self.length_out), 4)
        elif networkpacket.destination_ip_address() == self.host_ip:
            self.length_in.append(networkpacket.length())
            if networkpacket.length() > self.length_max_in:
                self.length_max_in = networkpacket.length()
            if networkpacket.length() < self.length_min_in:
                self.length_min_in = networkpacket.length()
            self.length_avg_in = round(sum(self.length_in) / len(self.length_in), 4)
            self.length_std_in = round(std(self.length_in), 4)

    def packet_count(self, networkpacket: Networkpacket):
        self.total_packet_count += 1
        if networkpacket.source_ip_address() == self.host_ip:
            self.total_out_packet_count += 1
        elif networkpacket.destination_ip_address() == self.host_ip:
            self.total_in_packet_count += 1

    def packets_bytes_per_s(self, networkpacket: Networkpacket):
        self.time_window_recording = networkpacket.timestamp_unix_in_ns() - self.init_time
        if self.time_window_recording > 0:
            time_window_in_s = float(self.time_window_recording) * float(0.000000001)
            self.packets_per_s = round(self.total_packet_count / time_window_in_s, 4)
            self.bytes_per_s = round(sum(self.length) / time_window_in_s, 4)

    def time_between_packets(self, networkpacket: Networkpacket):
        if self.last_packet_time_stamp:
            self.time_between_two_packets.append(networkpacket.timestamp_unix_in_ns() - self.last_packet_time_stamp)
            self.avg_time_between_two_packets = round(sum(self.time_between_two_packets) / len(self.time_between_two_packets))
            self.std_time_between_two_packets = round(std(self.time_between_two_packets))
        self.last_packet_time_stamp = networkpacket.timestamp_unix_in_ns()

    # Nur wenn flow initialisiert wird
    def num_connections_same_host(self, networkpacket: Networkpacket):
        if networkpacket.source_ip_address() == self.host_ip:
            if networkpacket.destination_ip_address() not in self.num_of_con_same_host:
                self.num_of_con_same_host[networkpacket.destination_ip_address()] = 1
            else:
                self.num_of_con_same_host[networkpacket.destination_ip_address()] += 1
            if networkpacket.destination_ip_address() not in self.num_of_con_to_same_host:
                self.num_of_con_to_same_host[networkpacket.destination_ip_address()] = 1
            else:
                self.num_of_con_to_same_host[networkpacket.destination_ip_address()] += 1
        if networkpacket.destination_ip_address() == self.host_ip:
            if networkpacket.source_ip_address() not in self.num_of_con_same_host:
                self.num_of_con_same_host[networkpacket.source_ip_address()] = 1
            else:
                self.num_of_con_same_host[networkpacket.source_ip_address()] += 1
            if networkpacket.source_ip_address() not in self.num_of_con_from_same_host:
                self.num_of_con_from_same_host[networkpacket.source_ip_address()] = 1
            else:
                self.num_of_con_from_same_host[networkpacket.source_ip_address()] += 1

    # Nur wenn flow initialisiert wird
    def perc_connections_same_host(self):
        for key in self.num_of_con_same_host:
            self.perc_of_con_same_host[key] = round(self.num_of_con_same_host[key] / self.flow_count, 4)
        for key in self.num_of_con_to_same_host:
            self.perc_of_con_to_same_host[key] = round(self.num_of_con_to_same_host[key] / self.flow_count, 4)
        for key in self.num_of_con_from_same_host:
            self.perc_of_con_from_same_host[key] = round(self.num_of_con_from_same_host[key] / self.flow_count, 4)

    def depends_on(self):
        return []

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._flows = []
        self.host_ip = None
        self.init_time = 0
        self.flow_count = 0
        self.total_packet_count = 0
        self.total_out_packet_count = 0
        self.total_in_packet_count = 0
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.length = []
        self.length_max = 0
        self.length_min = 99999
        self.length_avg = 0
        self.length_std = 0
        self.length_out = []
        self.length_max_out = 0
        self.length_min_out = 99999
        self.length_avg_out = 0
        self.length_std_out = 0
        self.length_in = []
        self.length_max_in = 0
        self.length_min_in = 99999
        self.length_avg_in = 0
        self.length_std_in = 0
        self.packets_per_s = 0
        self.bytes_per_s = 0
        self.last_packet_time_stamp = None
        self.time_between_two_packets = []
        self.time_window_recording = 0
        self.avg_time_between_two_packets = 0
        self.std_time_between_two_packets = 0
        self.num_of_con_same_host = {}
        self.num_of_con_to_same_host = {}
        self.num_of_con_from_same_host = {}
        self.perc_of_con_same_host = {}
        self.perc_of_con_to_same_host = {}
        self.perc_of_con_from_same_host = {}
