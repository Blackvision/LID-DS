from numpy import std


class ConnectionPacketsStd:

    def __init__(self):
        self.max_num_of_con_same_host = 0
        self.avg_packets_in_con = 0
        self.std_packets_in_con = 0

    def update(self, connections):
        packets_in_connection = []
        for connection in connections:
            packets_in_connection.append(len(connection.connection_packets))
            if len(connection.connection_packets) > self.max_num_of_con_same_host:
                self.max_num_of_con_same_host = len(connection.connection_packets)
        if packets_in_connection:
            self.avg_packets_in_con = round(sum(packets_in_connection) / len(packets_in_connection), 4)
            self.std_packets_in_con = round(std(packets_in_connection), 4)
