class Datapacket:
    """
    represents one datapacket
    """

    def __init__(self):
        self.recording_path = None

    def timestamp_unix_in_ns(self) -> int:
        """
        Returns:
            int: unix timestamp of datapacket
        """
        raise NotImplemented
