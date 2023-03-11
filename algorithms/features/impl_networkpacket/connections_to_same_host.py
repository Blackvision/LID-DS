from dataloader.networkpacket import Networkpacket


class ConnectionsToSameHost:

    def __init__(self, host_ip):
        self._host_ip = host_ip
        self._num_of_con_same_host = {}
        self.min_num_of_con_same_host = 9999
        self.max_num_of_con_same_host = 0
        self.avg_num_of_con_same_host = 0
        # self.std_num_of_con_same_host = 0

    def update(self, networkpacket: Networkpacket):
        if networkpacket.source_ip_address() == self._host_ip:
            if networkpacket.destination_ip_address() not in self._num_of_con_same_host:
                self._num_of_con_same_host[networkpacket.destination_ip_address()] = 1
            else:
                self._num_of_con_same_host[networkpacket.destination_ip_address()] += 1
            if self._num_of_con_same_host[networkpacket.destination_ip_address()] > self.max_num_of_con_same_host:
                self.max_num_of_con_same_host = self._num_of_con_same_host[networkpacket.destination_ip_address()]
            if self._num_of_con_same_host[networkpacket.destination_ip_address()] < self.min_num_of_con_same_host:
                self.min_num_of_con_same_host = self._num_of_con_same_host[networkpacket.destination_ip_address()]
        elif networkpacket.destination_ip_address() == self._host_ip:
            if networkpacket.source_ip_address() not in self._num_of_con_same_host:
                self._num_of_con_same_host[networkpacket.source_ip_address()] = 1
            else:
                self._num_of_con_same_host[networkpacket.source_ip_address()] += 1
            if self._num_of_con_same_host[networkpacket.source_ip_address()] > self.max_num_of_con_same_host:
                self.max_num_of_con_same_host = self._num_of_con_same_host[networkpacket.source_ip_address()]
            if self._num_of_con_same_host[networkpacket.source_ip_address()] < self.min_num_of_con_same_host:
                self.min_num_of_con_same_host = self._num_of_con_same_host[networkpacket.source_ip_address()]
        # else:
        #     key = networkpacket.source_ip_address() + networkpacket.destination_ip_address()
        #     if key not in self._num_of_con_same_host:
        #         self._num_of_con_same_host[key] = 1
        #     else:
        #         self._num_of_con_same_host[key] += 1
        if len(self._num_of_con_same_host) > 0:
            numbers = []
            for number in self._num_of_con_same_host.values():
                numbers.append(number)
            self.avg_num_of_con_same_host = round(sum(numbers) / len(numbers), 4)
            # self.std_num_of_con_same_host = round(std(numbers), 4)
