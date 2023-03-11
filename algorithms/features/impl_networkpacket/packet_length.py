from dataloader.networkpacket import Networkpacket


class PacketLength:

    def __init__(self):
        self._length = []
        self.length_max = 0
        self.length_min = 0
        self.length_avg = 0

    def update(self, networkpacket: Networkpacket):
        if len(self._length) <= 0:
            self.length_max = networkpacket.length()
            self.length_min = networkpacket.length()
        self._length.append(networkpacket.length())
        if networkpacket.length() > self.length_max:
            self.length_max = networkpacket.length()
        if networkpacket.length() < self.length_min:
            self.length_min = networkpacket.length()
        self.length_avg = round(sum(self._length) / len(self._length), 4)
