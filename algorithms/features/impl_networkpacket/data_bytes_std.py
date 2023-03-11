from numpy import std
from dataloader.networkpacket import Networkpacket


class DataBytesStd:

    def __init__(self):
        self._data_bytes = []
        self.data_bytes_max = 0
        self.data_bytes_min = 0
        self.data_bytes_avg = 0
        self.data_bytes_std = 0

    def update(self, networkpacket: Networkpacket):
        if networkpacket.data_length():
            if len(self._data_bytes) <= 0:
                self.data_bytes_max = networkpacket.data_length()
                self.data_bytes_min = networkpacket.data_length()
            self._data_bytes.append(int(networkpacket.data_length()))
            if networkpacket.data_length() > self.data_bytes_max:
                self.data_bytes_max = networkpacket.data_length()
            if networkpacket.data_length() < self.data_bytes_min:
                self.data_bytes_min = networkpacket.data_length()
            self.data_bytes_avg = round(sum(self._data_bytes) / len(self._data_bytes), 4)
            self.data_bytes_std = round(std(self._data_bytes), 4)
