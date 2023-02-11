from numpy import std

from algorithms.building_block import BuildingBlock
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
        self.add_packet(init_packet)

    def add_packet(self, networkpacket: Networkpacket):
        self.flow.append(networkpacket)

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
        self.connection_id = 0
        self.host_ip = None
        self.host_port = 0
        self.other_host_port = 0
        self.init_time = 0
        self.flow_count = 0
        self.total_packet_count = 0
        self.total_out_packet_count = 0
        self.total_in_packet_count = 0
        self.avg_packets_in_flows = 0
        self.std_packets_in_flows = 0
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.fin_flag_count_out = 0
        self.syn_flag_count_out = 0
        self.rst_flag_count_out = 0
        self.psh_flag_count_out = 0
        self.ack_flag_count_out = 0
        self.urg_flag_count_out = 0
        self.fin_flag_count_in = 0
        self.syn_flag_count_in = 0
        self.rst_flag_count_in = 0
        self.psh_flag_count_in = 0
        self.ack_flag_count_in = 0
        self.urg_flag_count_in = 0
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
        self.data_bytes = []
        self.data_bytes_avg = 0
        self.data_bytes_std = 0
        self.data_bytes_out = []
        self.data_bytes_out_avg = 0
        self.data_bytes_out_std = 0
        self.data_bytes_in = []
        self.data_bytes_in_avg = 0
        self.data_bytes_in_std = 0
        self.last_packet_time_stamp = None
        self.time_between_two_packets = []
        self.time_window_recording = 0
        self.avg_time_between_two_packets = 0
        self.std_time_between_two_packets = 0
        self.last_packet_time_stamp_out = None
        self.time_between_two_packets_out = []
        self.time_window_recording_out = 0
        self.avg_time_between_two_packets_out = 0
        self.std_time_between_two_packets_out = 0
        self.last_packet_time_stamp_in = None
        self.time_between_two_packets_in = []
        self.time_window_recording_in = 0
        self.avg_time_between_two_packets_in = 0
        self.std_time_between_two_packets_in = 0
        self.num_of_con_same_host = {}
        self.num_of_con_to_same_host = {}
        self.num_of_con_from_same_host = {}
        self.perc_of_con_same_host = {}
        self.perc_of_con_to_same_host = {}
        self.perc_of_con_from_same_host = {}
        self.num_of_con_same_host_pack = 0
        self.num_of_con_to_same_host_pack = 0
        self.num_of_con_from_same_host_pack = 0
        self.perc_of_con_same_host_pack = 0
        self.perc_of_con_to_same_host_pack = 0
        self.perc_of_con_from_same_host_pack = 0
        self.protocols = {}
        self.num_of_pack_same_first_layer_protocol = {}
        self.num_of_pack_same_second_layer_protocol = {}
        self.num_of_pack_same_third_layer_protocol = {}
        self.num_of_pack_same_fourth_layer_protocol = {}
        self.perc_of_pack_same_first_layer_protocol = {}
        self.perc_of_pack_same_second_layer_protocol = {}
        self.perc_of_pack_same_third_layer_protocol = {}
        self.perc_of_pack_same_fourth_layer_protocol = {}
        self.num_of_pack_same_first_layer_protocol_pack = 0
        self.num_of_pack_same_second_layer_protocol_pack = 0
        self.num_of_pack_same_third_layer_protocol_pack = 0
        self.num_of_pack_same_fourth_layer_protocol_pack = 0
        self.perc_of_pack_same_first_layer_protocol_pack = 0
        self.perc_of_pack_same_second_layer_protocol_pack = 0
        self.perc_of_pack_same_third_layer_protocol_pack = 0
        self.perc_of_pack_same_fourth_layer_protocol_pack = 0
        # (Flows nach timeout löschen (past two seconds))
        # (Percentage of connections that were to different hosts/ip)
        # (Percentage/Number of connections having the same/different portnumber/protocol)

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
                    self.connection_id = flow.connection_id
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
        value.append(self.fin_flag_count)
        value.append(self.syn_flag_count)
        value.append(self.rst_flag_count)
        value.append(self.psh_flag_count)
        value.append(self.ack_flag_count)
        value.append(self.urg_flag_count)
        # value.append(self.fin_flag_count_out)
        # value.append(self.syn_flag_count_out)
        # value.append(self.rst_flag_count_out)
        # value.append(self.psh_flag_count_out)
        # value.append(self.ack_flag_count_out)
        # value.append(self.urg_flag_count_out)
        # value.append(self.fin_flag_count_in)
        # value.append(self.syn_flag_count_in)
        # value.append(self.rst_flag_count_in)
        # value.append(self.psh_flag_count_in)
        # value.append(self.ack_flag_count_in)
        # value.append(self.urg_flag_count_in)
        value.append(self.total_packet_count)
        value.append(self.total_out_packet_count)
        value.append(self.total_in_packet_count)
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
        value.append(self.data_bytes_avg)
        value.append(self.data_bytes_std)
        # value.append(self.data_bytes_out_avg)
        # value.append(self.data_bytes_out_std)
        # value.append(self.data_bytes_in_avg)
        # value.append(self.data_bytes_in_std)
        value.append(self.packets_per_s)
        value.append(self.bytes_per_s)
        value.append(self.avg_time_between_two_packets)
        value.append(self.std_time_between_two_packets)
        # value.append(self.avg_time_between_two_packets_out)
        # value.append(self.std_time_between_two_packets_out)
        # value.append(self.avg_time_between_two_packets_in)
        # value.append(self.std_time_between_two_packets_in)
        # value.append(self.flow_count)
        value.append(self.num_of_con_same_host_pack)
        # value.append(self.num_of_con_to_same_host_pack)
        # value.append(self.num_of_con_from_same_host_pack)
        value.append(self.perc_of_con_same_host_pack)
        # value.append(self.perc_of_con_to_same_host_pack)
        # value.append(self.perc_of_con_from_same_host_pack)
        # value.append(self.num_of_pack_same_first_layer_protocol_pack)
        # value.append(self.num_of_pack_same_second_layer_protocol_pack)
        # value.append(self.num_of_pack_same_third_layer_protocol_pack)
        # value.append(self.num_of_pack_same_fourth_layer_protocol_pack)
        # value.append(self.perc_of_pack_same_first_layer_protocol_pack)
        # value.append(self.perc_of_pack_same_second_layer_protocol_pack)
        # value.append(self.perc_of_pack_same_third_layer_protocol_pack)
        # value.append(self.perc_of_pack_same_fourth_layer_protocol_pack)
        # value.append(self.time_window_recording)
        # value.append(self.connection_id)
        # value.append(networkpacket.length())
        return value

    def flows_append(self, networkpacket: Networkpacket):
        self.flow_count += 1
        flow = Flow(networkpacket, self.flow_count)
        self._flows.append(flow)
        self.connection_id = flow.connection_id
        self.num_connections_same_host(networkpacket)
        self.perc_connections_same_host()

    def flow_metrics(self, networkpacket: Networkpacket):
        self.flag_count(networkpacket)
        self.length_calculation(networkpacket)
        self.data_bytes_count(networkpacket)
        self.packet_count(networkpacket)
        self.packets_bytes_per_s(networkpacket)
        self.time_between_packets(networkpacket)
        self.connections_same_host(networkpacket)
        # self.ports(networkpacket)
        self.same_protocols(networkpacket)

    def average_flow_packets(self):
        packets_in_flows = []
        for flow in self._flows:
            packets_in_flows.append(len(flow.flow))
        if packets_in_flows:
            self.avg_packets_in_flows = round(sum(self.packets_in_flows) / len(self.packets_in_flows), 4)
            self.std_packets_in_flows = round(std(self.packets_in_flows), 4)

    def flag_count(self, networkpacket: Networkpacket):
        if networkpacket.transport_layer_protocol() == "tcp":
            self.fin_flag_count += networkpacket.tcp_fin_flag()
            self.syn_flag_count += networkpacket.tcp_syn_flag()
            self.rst_flag_count += networkpacket.tcp_rst_flag()
            self.psh_flag_count += networkpacket.tcp_psh_flag()
            self.ack_flag_count += networkpacket.tcp_ack_flag()
            self.urg_flag_count += networkpacket.tcp_urg_flag()
            if networkpacket.source_ip_address() == self.host_ip:
                self.fin_flag_count_out += networkpacket.tcp_fin_flag()
                self.syn_flag_count_out += networkpacket.tcp_syn_flag()
                self.rst_flag_count_out += networkpacket.tcp_rst_flag()
                self.psh_flag_count_out += networkpacket.tcp_psh_flag()
                self.ack_flag_count_out += networkpacket.tcp_ack_flag()
                self.urg_flag_count_out += networkpacket.tcp_urg_flag()
            elif networkpacket.destination_ip_address() == self.host_ip:
                self.fin_flag_count_in += networkpacket.tcp_fin_flag()
                self.syn_flag_count_in += networkpacket.tcp_syn_flag()
                self.rst_flag_count_in += networkpacket.tcp_rst_flag()
                self.psh_flag_count_in += networkpacket.tcp_psh_flag()
                self.ack_flag_count_in += networkpacket.tcp_ack_flag()
                self.urg_flag_count_in += networkpacket.tcp_urg_flag()

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

    def data_bytes_count(self, networkpacket: Networkpacket):
        if networkpacket.data():
            self.data_bytes.append(int(networkpacket.data_length()))
            self.data_bytes_avg = round(sum(self.data_bytes) / len(self.data_bytes), 4)
            self.data_bytes_std = round(std(self.data_bytes), 4)
            if networkpacket.source_ip_address() == self.host_ip:
                self.data_bytes_out.append(int(networkpacket.data_length()))
                self.data_bytes_out_avg = round(sum(self.data_bytes_out) / len(self.data_bytes_out), 4)
                self.data_bytes_out_std = round(std(self.data_bytes_out), 4)
            elif networkpacket.destination_ip_address() == self.host_ip:
                self.data_bytes_in.append(int(networkpacket.data_length()))
                self.data_bytes_in_avg = round(sum(self.data_bytes_in) / len(self.data_bytes_in), 4)
                self.data_bytes_in_std = round(std(self.data_bytes_in), 4)

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
        if networkpacket.source_ip_address() == self.host_ip:
            if self.last_packet_time_stamp_out:
                self.time_between_two_packets_out.append(networkpacket.timestamp_unix_in_ns() - self.last_packet_time_stamp_out)
                self.avg_time_between_two_packets_out = round(
                    sum(self.time_between_two_packets_out) / len(self.time_between_two_packets_out))
                self.std_time_between_two_packets_out = round(std(self.time_between_two_packets_out))
            self.last_packet_time_stamp_out = networkpacket.timestamp_unix_in_ns()
        elif networkpacket.destination_ip_address() == self.host_ip:
            if self.last_packet_time_stamp_in:
                self.time_between_two_packets_in.append(networkpacket.timestamp_unix_in_ns() - self.last_packet_time_stamp_in)
                self.avg_time_between_two_packets_in = round(
                    sum(self.time_between_two_packets_in) / len(self.time_between_two_packets_in))
                self.std_time_between_two_packets_in = round(std(self.time_between_two_packets_in))
            self.last_packet_time_stamp_in = networkpacket.timestamp_unix_in_ns()

    def connections_same_host(self, networkpacket: Networkpacket):
        self.num_of_con_same_host_pack = 0
        self.num_of_con_to_same_host_pack = 0
        self.num_of_con_from_same_host_pack = 0
        self.perc_of_con_same_host_pack = 0
        self.perc_of_con_to_same_host_pack = 0
        self.perc_of_con_from_same_host_pack = 0
        if networkpacket.source_ip_address() == self.host_ip:
            if networkpacket.destination_ip_address() in self.num_of_con_same_host:
                self.num_of_con_same_host_pack = self.num_of_con_same_host[networkpacket.destination_ip_address()]
                self.perc_of_con_same_host_pack = self.perc_of_con_same_host[networkpacket.destination_ip_address()]
            if networkpacket.destination_ip_address() in self.num_of_con_to_same_host:
                self.num_of_con_to_same_host_pack = self.num_of_con_to_same_host[networkpacket.destination_ip_address()]
                self.perc_of_con_to_same_host_pack = self.perc_of_con_to_same_host[networkpacket.destination_ip_address()]
            if networkpacket.destination_ip_address() in self.num_of_con_from_same_host:
                self.num_of_con_from_same_host_pack = self.num_of_con_from_same_host[networkpacket.destination_ip_address()]
                self.perc_of_con_from_same_host_pack = self.perc_of_con_from_same_host[networkpacket.destination_ip_address()]
        if networkpacket.destination_ip_address() == self.host_ip:
            if networkpacket.source_ip_address() in self.num_of_con_same_host:
                self.num_of_con_same_host_pack = self.num_of_con_same_host[networkpacket.source_ip_address()]
                self.perc_of_con_same_host_pack = self.perc_of_con_same_host[networkpacket.source_ip_address()]
            if networkpacket.source_ip_address() in self.num_of_con_to_same_host:
                self.num_of_con_to_same_host_pack = self.num_of_con_to_same_host[networkpacket.source_ip_address()]
                self.perc_of_con_to_same_host_pack = self.perc_of_con_to_same_host[networkpacket.source_ip_address()]
            if networkpacket.source_ip_address() in self.num_of_con_from_same_host:
                self.num_of_con_from_same_host_pack = self.num_of_con_from_same_host[networkpacket.source_ip_address()]
                self.perc_of_con_from_same_host_pack = self.perc_of_con_from_same_host[networkpacket.source_ip_address()]

    def ports(self, networkpacket: Networkpacket):
        if (networkpacket.source_ip_address() == self.host_ip and
                networkpacket.source_port() and networkpacket.destination_port()):
            self.host_port = networkpacket.source_port()
            self.other_host_port = networkpacket.destination_port()
        elif (networkpacket.destination_ip_address() == self.host_ip and
                networkpacket.source_port() and networkpacket.destination_port()):
            self.host_port = networkpacket.destination_port()
            self.other_host_port = networkpacket.source_port()
        else:
            self.host_port = 0
            self.other_host_port = 0

    def same_protocols(self, networkpacket: Networkpacket):
        self.perc_of_pack_same_first_layer_protocol_pack = 0
        self.perc_of_pack_same_second_layer_protocol_pack = 0
        self.perc_of_pack_same_third_layer_protocol_pack = 0
        self.perc_of_pack_same_fourth_layer_protocol_pack = 0
        if networkpacket.first_layer_protocol():
            self.check_protocol(networkpacket.first_layer_protocol())
            if self.protocols[networkpacket.first_layer_protocol()] not in self.num_of_pack_same_first_layer_protocol:
                self.num_of_pack_same_first_layer_protocol[self.protocols[networkpacket.first_layer_protocol()]] = 1
            else:
                self.num_of_pack_same_first_layer_protocol[self.protocols[networkpacket.first_layer_protocol()]] += 1
            self.num_of_pack_same_first_layer_protocol_pack = self.num_of_pack_same_first_layer_protocol[self.protocols[networkpacket.first_layer_protocol()]]
        if networkpacket.second_layer_protocol():
            self.check_protocol(networkpacket.second_layer_protocol())
            if self.protocols[networkpacket.second_layer_protocol()] not in self.num_of_pack_same_second_layer_protocol:
                self.num_of_pack_same_second_layer_protocol[self.protocols[networkpacket.second_layer_protocol()]] = 1
            else:
                self.num_of_pack_same_second_layer_protocol[self.protocols[networkpacket.second_layer_protocol()]] += 1
            self.num_of_pack_same_second_layer_protocol_pack = self.num_of_pack_same_second_layer_protocol[self.protocols[networkpacket.second_layer_protocol()]]
        if networkpacket.third_layer_protocol():
            self.check_protocol(networkpacket.third_layer_protocol())
            if self.protocols[networkpacket.third_layer_protocol()] not in self.num_of_pack_same_third_layer_protocol:
                self.num_of_pack_same_third_layer_protocol[self.protocols[networkpacket.third_layer_protocol()]] = 1
            else:
                self.num_of_pack_same_third_layer_protocol[self.protocols[networkpacket.third_layer_protocol()]] += 1
            self.num_of_pack_same_third_layer_protocol_pack = self.num_of_pack_same_third_layer_protocol[self.protocols[networkpacket.third_layer_protocol()]]
        if networkpacket.fourth_layer_protocol():
            self.check_protocol(networkpacket.fourth_layer_protocol())
            if self.protocols[networkpacket.fourth_layer_protocol()] not in self.num_of_pack_same_fourth_layer_protocol:
                self.num_of_pack_same_fourth_layer_protocol[self.protocols[networkpacket.fourth_layer_protocol()]] = 1
            else:
                self.num_of_pack_same_fourth_layer_protocol[self.protocols[networkpacket.fourth_layer_protocol()]] += 1
            self.num_of_pack_same_fourth_layer_protocol_pack = self.num_of_pack_same_fourth_layer_protocol[self.protocols[networkpacket.fourth_layer_protocol()]]
        for key in self.num_of_pack_same_first_layer_protocol:
            self.perc_of_pack_same_first_layer_protocol[key] = round(self.num_of_pack_same_first_layer_protocol[key] / self.total_packet_count, 4)
            self.perc_of_pack_same_first_layer_protocol_pack = self.perc_of_pack_same_first_layer_protocol[key]
        for key in self.num_of_pack_same_second_layer_protocol:
            self.perc_of_pack_same_second_layer_protocol[key] = round(self.num_of_pack_same_second_layer_protocol[key] / self.total_packet_count, 4)
            self.perc_of_pack_same_second_layer_protocol_pack = self.perc_of_pack_same_second_layer_protocol[key]
        for key in self.num_of_pack_same_third_layer_protocol:
            self.perc_of_pack_same_third_layer_protocol[key] = round(self.num_of_pack_same_third_layer_protocol[key] / self.total_packet_count, 4)
            self.perc_of_pack_same_third_layer_protocol_pack = self.perc_of_pack_same_third_layer_protocol[key]
        for key in self.num_of_pack_same_fourth_layer_protocol:
            self.perc_of_pack_same_fourth_layer_protocol[key] = round(self.num_of_pack_same_fourth_layer_protocol[key] / self.total_packet_count, 4)
            self.perc_of_pack_same_fourth_layer_protocol_pack = self.perc_of_pack_same_fourth_layer_protocol[key]

    def check_protocol(self, protocol):
        if protocol not in self.protocols:
            self.protocols[protocol] = len(self.protocols) + 1

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
        self.connection_id = 0
        self.host_ip = None
        self.host_port = 0
        self.other_host_port = 0
        self.init_time = 0
        self.flow_count = 0
        self.total_packet_count = 0
        self.total_out_packet_count = 0
        self.total_in_packet_count = 0
        self.avg_packets_in_flows = 0
        self.std_packets_in_flows = 0
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.fin_flag_count_out = 0
        self.syn_flag_count_out = 0
        self.rst_flag_count_out = 0
        self.psh_flag_count_out = 0
        self.ack_flag_count_out = 0
        self.urg_flag_count_out = 0
        self.fin_flag_count_in = 0
        self.syn_flag_count_in = 0
        self.rst_flag_count_in = 0
        self.psh_flag_count_in = 0
        self.ack_flag_count_in = 0
        self.urg_flag_count_in = 0
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
        self.data_bytes = []
        self.data_bytes_avg = 0
        self.data_bytes_std = 0
        self.data_bytes_out = []
        self.data_bytes_out_avg = 0
        self.data_bytes_out_std = 0
        self.data_bytes_in = []
        self.data_bytes_in_avg = 0
        self.data_bytes_in_std = 0
        self.last_packet_time_stamp = None
        self.time_between_two_packets = []
        self.time_window_recording = 0
        self.avg_time_between_two_packets = 0
        self.std_time_between_two_packets = 0
        self.last_packet_time_stamp_out = None
        self.time_between_two_packets_out = []
        self.time_window_recording_out = 0
        self.avg_time_between_two_packets_out = 0
        self.std_time_between_two_packets_out = 0
        self.last_packet_time_stamp_in = None
        self.time_between_two_packets_in = []
        self.time_window_recording_in = 0
        self.avg_time_between_two_packets_in = 0
        self.std_time_between_two_packets_in = 0
        self.num_of_con_same_host = {}
        self.num_of_con_to_same_host = {}
        self.num_of_con_from_same_host = {}
        self.perc_of_con_same_host = {}
        self.perc_of_con_to_same_host = {}
        self.perc_of_con_from_same_host = {}
        self.num_of_con_same_host_pack = 0
        self.num_of_con_to_same_host_pack = 0
        self.num_of_con_from_same_host_pack = 0
        self.perc_of_con_same_host_pack = 0
        self.perc_of_con_to_same_host_pack = 0
        self.perc_of_con_from_same_host_pack = 0
        self.protocols = {}
        self.num_of_pack_same_first_layer_protocol = {}
        self.num_of_pack_same_second_layer_protocol = {}
        self.num_of_pack_same_third_layer_protocol = {}
        self.num_of_pack_same_fourth_layer_protocol = {}
        self.perc_of_pack_same_first_layer_protocol = {}
        self.perc_of_pack_same_second_layer_protocol = {}
        self.perc_of_pack_same_third_layer_protocol = {}
        self.perc_of_pack_same_fourth_layer_protocol = {}
        self.num_of_pack_same_first_layer_protocol_pack = 0
        self.num_of_pack_same_second_layer_protocol_pack = 0
        self.num_of_pack_same_third_layer_protocol_pack = 0
        self.num_of_pack_same_fourth_layer_protocol_pack = 0
        self.perc_of_pack_same_first_layer_protocol_pack = 0
        self.perc_of_pack_same_second_layer_protocol_pack = 0
        self.perc_of_pack_same_third_layer_protocol_pack = 0
        self.perc_of_pack_same_fourth_layer_protocol_pack = 0
