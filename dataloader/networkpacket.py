from dataloader.datapacket import Datapacket


class Networkpacket(Datapacket):
    """
    represents one network packet
    """

    def __init__(self):
        self.recording_path = None

    def internet_layer_protocol(self) -> str:
        """
        Returns:
            str: internet layer protocol
        """
        raise NotImplemented

    def source_ip_address(self) -> str:
        """
        Returns:
            str: source ip address
        """
        raise NotImplemented

    def destination_ip_address(self) -> str:
        """
        Returns:
            str: destination ip address
        """
        raise NotImplemented

    def transport_layer_protocol(self) -> str:
        """
        Returns:
            str: transport layer protocol
        """
        raise NotImplemented

    def source_port(self) -> int:
        """
        Returns:
            int: source port
        """
        raise NotImplemented

    def destination_port(self) -> int:
        """
        Returns:
            int: destination port
        """
        raise NotImplemented

    def timestamp_datetime(self) -> int:
        """
        Returns:
            int: timestamp
        """
        raise NotImplemented

    def length(self) -> int:
        """
        Returns:
            int: network packet length
        """
        raise NotImplemented

    def data(self) -> str:
        """
        Returns:
            string: data
        """
        raise NotImplemented

    def data_length(self) -> int:
        """
        Returns:
            int: data length
        """
        raise NotImplemented

    def tcp_fin_flag(self) -> int:
        """
        Returns:
            int: fin flag
        """
        raise NotImplemented

    def tcp_syn_flag(self) -> int:
        """
        Returns:
            int: syn flag
        """
        raise NotImplemented

    def tcp_rst_flag(self) -> int:
        """
        Returns:
            int: rst flag
        """
        raise NotImplemented

    def tcp_psh_flag(self) -> int:
        """
        Returns:
            int: psh flag
        """
        raise NotImplemented

    def tcp_ack_flag(self) -> int:
        """
        Returns:
            int: ack flag
        """
        raise NotImplemented

    def tcp_urg_flag(self) -> int:
        """
        Returns:
            int: urg flag
        """
        raise NotImplemented

    def protocol_stack(self) -> str:
        """
        Returns:
            str: protocol stack
        """
        raise NotImplemented
