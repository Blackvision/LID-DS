import re
from datetime import datetime

from dataloader.networkpacket import Networkpacket


class Networkpacket2021(Networkpacket):
    """
    represents one network packet as an object created from a object out of an LID-DS 2021 recording
    features lazy instantiation of network packet attributes
    """

    def __init__(self, recording_path: str, networkpacket_frame):
        self.recording_path = recording_path
        self.networkpacket_frame = networkpacket_frame
        self._timestamp_unix_in_ns = int(re.sub('\.', '', self.networkpacket_frame.sniff_timestamp))
        self._timestamp_datetime = datetime.fromtimestamp(int(self._timestamp_unix_in_ns) * 10 ** -9)
        self._length = int(self.networkpacket_frame.length)
        self._protocol_stack = self.networkpacket_frame.frame_info.protocols

        if hasattr(self.networkpacket_frame, 'ipv6'):
            self._internet_layer_protocol = "ipv6"
            self._source_ip_address = self.networkpacket_frame.ipv6.host
            self._destination_ip_address = self.networkpacket_frame.ipv6.dst
        elif hasattr(self.networkpacket_frame, 'ip'):
            self._internet_layer_protocol = "ipv4"
            self._source_ip_address = self.networkpacket_frame.ip.host
            self._destination_ip_address = self.networkpacket_frame.ip.dst
        elif hasattr(self.networkpacket_frame, 'arp'):
            self._internet_layer_protocol = "arp"
            self._source_ip_address = self.networkpacket_frame.arp.src_proto_ipv4
            self._destination_ip_address = self.networkpacket_frame.arp.dst_proto_ipv4
        else:
            self._internet_layer_protocol = None
            self._source_ip_address = None
            self._destination_ip_address = None

        if hasattr(self.networkpacket_frame, 'tcp'):
            self._transport_layer_protocol = "tcp"
            self._source_port = int(self.networkpacket_frame.tcp.port)
            self._destination_port = int(self.networkpacket_frame.tcp.dstport)
            if hasattr(self.networkpacket_frame.tcp, 'payload'):
                self._data = self.networkpacket_frame.tcp.payload
                self._data_length = int(self.networkpacket_frame.tcp.len)
            else:
                self._data = None
                self._data_length = None
        elif hasattr(self.networkpacket_frame, 'udp'):
            self._transport_layer_protocol = "udp"
            self._source_port = int(self.networkpacket_frame.udp.port)
            self._destination_port = int(self.networkpacket_frame.udp.dstport)
            if hasattr(self.networkpacket_frame.udp, 'payload'):
                self._data = self.networkpacket_frame.udp.payload
                self._data_length = int(self.networkpacket_frame.udp.length)
            else:
                self._data = None
                self._data_length = None
        else:
            self._transport_layer_protocol = "0"
            self._source_port = None
            self._destination_port = None
            self._data = None
            self._data_length = None

        if self._transport_layer_protocol == "tcp":
            self._fin_flag = int(self.networkpacket_frame.tcp.flags_fin)
            self._syn_flag = int(self.networkpacket_frame.tcp.flags_syn)
            self._rst_flag = int(self.networkpacket_frame.tcp.flags_reset)
            self._psh_flag = int(self.networkpacket_frame.tcp.flags_push)
            self._ack_flag = int(self.networkpacket_frame.tcp.flags_ack)
            self._urg_flag = int(self.networkpacket_frame.tcp.flags_urg)
        else:
            self._fin_flag = None
            self._syn_flag = None
            self._rst_flag = None
            self._psh_flag = None
            self._ack_flag = None
            self._urg_flag = None

    def internet_layer_protocol(self) -> str:
        """
        Returns:
            str: internet layer protocol
        """
        return self._internet_layer_protocol

    def source_ip_address(self) -> str:
        """
        Returns:
            str: source ip address
        """
        return self._source_ip_address

    def destination_ip_address(self) -> str:
        """
        Returns:
            str: destination ip address
        """
        return self._destination_ip_address

    def transport_layer_protocol(self) -> str:
        """
        Returns:
            str: transport layer protocol
        """
        return self._transport_layer_protocol

    def source_port(self) -> int:
        """
        Returns:
            int: source port
        """
        return self._source_port

    def destination_port(self) -> int:
        """
        Returns:
            int: destination port
        """
        return self._destination_port

    def timestamp_unix_in_ns(self) -> int:
        """
        Returns:
            int: unix timestamp
        """
        return self._timestamp_unix_in_ns

    def timestamp_datetime(self) -> datetime:
        """
        Returns:
            int: timestamp in ns
        """
        return self._timestamp_datetime

    def length(self) -> int:
        """
        Returns:
            int: length
        """
        return self._length

    def data(self) -> str:
        """
        Returns:
            string: data
        """
        return self._data

    def data_length(self) -> int:
        """
        Returns:
            int: data length
        """
        return self._data_length

    def tcp_fin_flag(self) -> int:
        """
        Returns:
            int: fin flag
        """
        return self._fin_flag

    def tcp_syn_flag(self) -> int:
        """
        Returns:
            int: syn flag
        """
        return self._syn_flag

    def tcp_rst_flag(self) -> int:
        """
        Returns:
            int: rst flag
        """
        return self._rst_flag

    def tcp_psh_flag(self) -> int:
        """
        Returns:
            int: psh flag
        """
        return self._psh_flag

    def tcp_ack_flag(self) -> int:
        """
        Returns:
            int: ack flag
        """
        return self._ack_flag

    def tcp_urg_flag(self) -> int:
        """
        Returns:
            int: urg flag
        """
        return self._urg_flag

    def protocol_stack(self) -> str:
        """
        Returns:
            str: protocol stack
        """
        return self._protocol_stack