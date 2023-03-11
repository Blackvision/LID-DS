from dataloader.networkpacket import Networkpacket


class PacketsBytesPerS:

    def __init__(self, init_time):
        self._init_time = init_time
        self._length = []
        self.total_packet_count = 0
        self.packets_per_s = 0
        self.bytes_per_s = 0

    def update(self, networkpacket: Networkpacket):
        self.total_packet_count += 1
        self._length.append(networkpacket.length())
        time_window_recording = networkpacket.timestamp_unix_in_ns() - self._init_time
        if time_window_recording > 0:
            time_window_in_s = float(time_window_recording) * float(0.000000001)
            self.packets_per_s = round(self.total_packet_count / time_window_in_s, 4)
            self.bytes_per_s = round(sum(self._length) / time_window_in_s, 4)
