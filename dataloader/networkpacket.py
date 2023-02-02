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

    def highest_layer_protocol(self) -> str:
        """
        Returns:
            str: highest layer protocol
        """
        raise NotImplemented

    def land(self) -> int:
        """
        Returns:
            int: if source and destination IP addresses and port numbers are equal then, this variable takes value 1 else 0
        """
        raise NotImplemented

    def layer_count(self) -> int:
        """
        Returns:
            int: Number of layers in a network packet
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

    def transport_layer_checksum(self) -> str:
        """
        Returns:
            string: transport layer checksum
        """
        raise NotImplemented

    def transport_layer_checksum_status(self) -> str:
        """
        Returns:
            string: transport layer checksum status
        """
        raise NotImplemented

    def transport_layer_flags(self) -> str:
        """
        Returns:
            string: transport layer flags
        """
        raise NotImplemented
