from dataloader.networkpacket import Networkpacket


class TimeBetweenPackets:

    def __init__(self):
        self._last_packet_time_stamp = None
        self._time_between_packets = []
        self.avg_time_between_two_packets = 0

    def update(self, networkpacket: Networkpacket):
        if self._last_packet_time_stamp:
            self._time_between_packets.append(networkpacket.timestamp_unix_in_ns() - self._last_packet_time_stamp)
            self.avg_time_between_two_packets = round(sum(self._time_between_packets) / len(self._time_between_packets))
        self._last_packet_time_stamp = networkpacket.timestamp_unix_in_ns()