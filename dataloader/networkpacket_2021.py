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
        self._internet_layer_protocol = None
        self._source_ip_address = None
        self._destination_ip_address = None
        self._transport_layer_protocol = None
        self._source_port = None
        self._destination_port = None
        self._highest_layer_protocol = None
        self._land = None
        self._layer_count = None
        self._timestamp_unix_in_ns = None
        self._timestamp_datetime = None
        self._length = None
        self._data = None
        self._data_length = None
        self._transport_layer_checksum = None
        self._transport_layer_checksum_status = None
        self._transport_layer_flags = None
        self._fin_flag = None
        self._syn_flag = None
        self._rst_flag = None
        self._psh_flag = None
        self._ack_flag = None
        self._urg_flag = None
        self._first_layer_protocol = None
        self._second_layer_protocol = None
        self._third_layer_protocol = None
        self._fourth_layer_protocol = None

    def internet_layer_protocol(self) -> str:
        """
        Returns:
            str: internet layer protocol
        """
        if self._internet_layer_protocol is None:
            if hasattr(self.networkpacket_frame, 'ipv6'):
                self._internet_layer_protocol = "ipv6"
            elif hasattr(self.networkpacket_frame, 'ip'):
                self._internet_layer_protocol = "ipv4"
            elif hasattr(self.networkpacket_frame, 'arp'):
                self._internet_layer_protocol = "arp"
        return self._internet_layer_protocol

    def source_ip_address(self) -> str:
        """
        Returns:
            str: source ip address
        """
        if self._source_ip_address is None:
            if hasattr(self.networkpacket_frame, 'ipv6'):
                self._source_ip_address = self.networkpacket_frame.ipv6.host
            elif hasattr(self.networkpacket_frame, 'ip'):
                self._source_ip_address = self.networkpacket_frame.ip.host
            elif hasattr(self.networkpacket_frame, 'arp'):
                self._source_ip_address = self.networkpacket_frame.arp.src_proto_ipv4
        return self._source_ip_address

    def destination_ip_address(self) -> str:
        """
        Returns:
            str: destination ip address
        """
        if self._destination_ip_address is None:
            if hasattr(self.networkpacket_frame, 'ipv6'):
                self._destination_ip_address = self.networkpacket_frame.ipv6.dst
            elif hasattr(self.networkpacket_frame, 'ip'):
                self._destination_ip_address = self.networkpacket_frame.ip.dst
            elif hasattr(self.networkpacket_frame, 'arp'):
                self._destination_ip_address = self.networkpacket_frame.arp.dst_proto_ipv4
        return self._destination_ip_address

    def transport_layer_protocol(self) -> str:
        """
        Returns:
            str: transport layer protocol
        """
        if self._transport_layer_protocol is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._transport_layer_protocol = "tcp"
            elif hasattr(self.networkpacket_frame, 'udp'):
                self._transport_layer_protocol = "udp"
            else:
                self._transport_layer_protocol = "0"
        return self._transport_layer_protocol

    def source_port(self) -> int:
        """
        Returns:
            int: source port
        """
        if self._source_port is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._source_port = int(self.networkpacket_frame.tcp.port)
            elif hasattr(self.networkpacket_frame, 'udp'):
                self._source_port = int(self.networkpacket_frame.udp.port)
            else:
                self._source_port = None
        return self._source_port

    def destination_port(self) -> int:
        """
        Returns:
            int: destination port
        """
        if self._destination_port is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._destination_port = int(self.networkpacket_frame.tcp.dstport)
            elif hasattr(self.networkpacket_frame, 'udp'):
                self._destination_port = int(self.networkpacket_frame.udp.dstport)
            else:
                self._destination_port = None
        return self._destination_port

    def highest_layer_protocol(self) -> str:
        """
        Returns:
            str: highest layer protocol
        """
        if self._highest_layer_protocol is None:
            self._highest_layer_protocol = self.networkpacket_frame.highest_layer
        return self._highest_layer_protocol

    def first_layer_protocol(self) -> str:
        """
        Returns:
            first_layer_protocol
        """
        if self._first_layer_protocol is None:
            if len(self.networkpacket_frame.layers) > 1:
                self._first_layer_protocol = self.networkpacket_frame.layers[1].layer_name
        return self._first_layer_protocol

    def second_layer_protocol(self) -> str:
        """
        Returns:
            second_layer_protocol
        """
        if self._second_layer_protocol is None:
            if len(self.networkpacket_frame.layers) > 2:
                self._second_layer_protocol = self.networkpacket_frame.layers[2].layer_name
        return self._second_layer_protocol

    def third_layer_protocol(self) -> str:
        """
        Returns:
            third_layer_protocol
        """
        if self._third_layer_protocol is None:
            if len(self.networkpacket_frame.layers) > 3:
                self._third_layer_protocol = self.networkpacket_frame.layers[3].layer_name
        return self._third_layer_protocol

    def fourth_layer_protocol(self) -> str:
        """
        Returns:
            fourth_layer_protocol
        """
        if self._fourth_layer_protocol is None:
            if len(self.networkpacket_frame.layers) > 4:
                self._fourth_layer_protocol = self.networkpacket_frame.layers[4].layer_name
        return self._fourth_layer_protocol

    def layer_count(self) -> int:
        """
        Returns:
            int: Number of layers in a network packet
        """
        if self._layer_count is None:
            self._layer_count = len(self.networkpacket_frame.layers)
        return self._layer_count

    def timestamp_unix_in_ns(self) -> int:
        """
        Returns:
            int: unix timestamp
        """
        if self._timestamp_unix_in_ns is None:
            self._timestamp_unix_in_ns = int(re.sub('\.', '', self.networkpacket_frame.sniff_timestamp))
        return self._timestamp_unix_in_ns

    def timestamp_datetime(self) -> datetime:
        """
        Returns:
            int: timestamp in ns
        """
        if self._timestamp_datetime is None:
            self._timestamp_datetime = datetime.fromtimestamp(int(self.timestamp_unix_in_ns()) * 10 ** -9)
        return self._timestamp_datetime

    def length(self) -> int:
        """
        Returns:
            int: length
        """
        if self._length is None:
            self._length = int(self.networkpacket_frame.length)
        return self._length

    def data(self) -> str:
        """
        Returns:
            string: data
        """
        if self._data is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                if hasattr(self.networkpacket_frame.tcp, 'payload'):
                    self._data = self.networkpacket_frame.tcp.payload
            elif hasattr(self.networkpacket_frame, 'udp'):
                if hasattr(self.networkpacket_frame.udp, 'payload'):
                    self._data = self.networkpacket_frame.udp.payload
            else:
                self._data = None
        return self._data

    def data_length(self) -> int:
        """
        Returns:
            int: data length
        """
        if self._data_length is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                if hasattr(self.networkpacket_frame.tcp, 'payload'):
                    self._data_length = self.networkpacket_frame.tcp.len
            elif hasattr(self.networkpacket_frame, 'udp'):
                if hasattr(self.networkpacket_frame.udp, 'payload'):
                    self._data_length = self.networkpacket_frame.udp.length
            else:
                self._data_length = None
        return self._data_length

    def transport_layer_checksum(self) -> str:
        """
        Returns:
            string: transport layer checksum
        """
        if self._transport_layer_checksum is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._transport_layer_checksum = self.networkpacket_frame.tcp.checksum
            elif hasattr(self.networkpacket_frame, 'udp'):
                self._transport_layer_checksum = self.networkpacket_frame.udp.checksum
            else:
                self._transport_layer_checksum = None
        return self._transport_layer_checksum

    def transport_layer_checksum_status(self) -> str:
        """
        Returns:
            string: transport layer checksum status
        """
        if self._transport_layer_checksum_status is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._transport_layer_checksum_status = int(self.networkpacket_frame.tcp.checksum_status)
            elif hasattr(self.networkpacket_frame, 'udp'):
                self._transport_layer_checksum_status = int(self.networkpacket_frame.udp.checksum_status)
            else:
                self._transport_layer_checksum_status = None
        return self._transport_layer_checksum_status

    def transport_layer_flags(self) -> str:
        """
        Returns:
            string: transport layer flags
        """
        if self._transport_layer_flags is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                flags = []
                flags.append(int(self.networkpacket_frame.tcp.flags_urg))
                flags.append(int(self.networkpacket_frame.tcp.flags_ack))
                flags.append(int(self.networkpacket_frame.tcp.flags_push))
                flags.append(int(self.networkpacket_frame.tcp.flags_reset))
                flags.append(int(self.networkpacket_frame.tcp.flags_syn))
                flags.append(int(self.networkpacket_frame.tcp.flags_fin))
                self._transport_layer_flags = flags
            else:
                self._transport_layer_flags = None
        return self._transport_layer_flags

    def tcp_fin_flag(self) -> int:
        """
        Returns:
            int: fin flag
        """
        if self._fin_flag is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._fin_flag = int(self.networkpacket_frame.tcp.flags_fin)
            else:
                self._fin_flag = None
        return self._fin_flag

    def tcp_syn_flag(self) -> int:
        """
        Returns:
            int: syn flag
        """
        if self._syn_flag is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._syn_flag = int(self.networkpacket_frame.tcp.flags_syn)
            else:
                self._syn_flag = None
        return self._syn_flag

    def tcp_rst_flag(self) -> int:
        """
        Returns:
            int: rst flag
        """
        if self._rst_flag is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._rst_flag = int(self.networkpacket_frame.tcp.flags_reset)
            else:
                self._rst_flag = None
        return self._rst_flag

    def tcp_psh_flag(self) -> int:
        """
        Returns:
            int: psh flag
        """
        if self._psh_flag is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._psh_flag = int(self.networkpacket_frame.tcp.flags_push)
            else:
                self._psh_flag = None
        return self._psh_flag

    def tcp_ack_flag(self) -> int:
        """
        Returns:
            int: ack flag
        """
        if self._ack_flag is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._ack_flag = int(self.networkpacket_frame.tcp.flags_ack)
            else:
                self._ack_flag = None
        return self._ack_flag

    def tcp_urg_flag(self) -> int:
        """
        Returns:
            int: urg flag
        """
        if self._urg_flag is None:
            if hasattr(self.networkpacket_frame, 'tcp'):
                self._urg_flag = int(self.networkpacket_frame.tcp.flags_urg)
            else:
                self._urg_flag = None
        return self._urg_flag
