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
