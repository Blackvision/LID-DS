from dataloader.networkpacket import Networkpacket
from datetime import datetime
import re


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
        self._transport_layer_checksum = None
        self._transport_layer_checksum_status = None
        self._transport_layer_flags = None

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
                self._transport_layer_protocol = None
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

    def land(self) -> int:
        """
        Returns:
            int: if source and destination IP addresses and port numbers are equal then, this variable takes value 1 else 0
        """
        if self._land is None:
            if self._source_ip_address == self._destination_ip_address:
                if self._source_port == self._destination_port:
                    self._land = 1
            else:
                self._land = 0
        return self._land

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
            # self._timestamp_datetime = self.networkpacket_frame.sniff_time
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


