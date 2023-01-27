from dataloader.datapacket import Datapacket


class Networkpacket(Datapacket):
    """
    represents one network packet
    """

    def __init__(self):
        self.recording_path = None

    def source_ip_address(self) -> int:
        """
        Returns:
            int: source ip address
        """
        raise NotImplemented

    def destination_ip_address(self) -> int:
        """
        Returns:
            int: destination ip address
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

    def transport_layer_protocol(self) -> str:
        """
        Returns:
            int: destination port
        """
        raise NotImplemented

    def internet_layer_protocol(self) -> str:
        """
        Returns:
            str: internet layer protocol
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
            int: timestamp
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
            string: data
        """
        raise NotImplemented

    def transport_layer_checksum_status(self) -> str:
        """
        Returns:
            string: data
        """
        raise NotImplemented

    def transport_layer_flags(self) -> str:
        """
        Returns:
            string: data
        """
        raise NotImplemented
