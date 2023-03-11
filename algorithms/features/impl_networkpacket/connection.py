from dataloader.networkpacket import Networkpacket


class Connection:

    def __init__(self, init_packet: Networkpacket):
        self.init_time = init_packet.timestamp_unix_in_ns()
        self.init_source_ip = init_packet.source_ip_address()
        self.init_destination_ip = init_packet.destination_ip_address()
        self.init_source_port = init_packet.source_port()
        self.init_destination_port = init_packet.destination_port()
        self.connection_packets = []
        self.add_packet(init_packet)

    def add_packet(self, networkpacket: Networkpacket):
        self.connection_packets.append(networkpacket)

    def belongs_to_connection(self, networkpacket: Networkpacket):
        if (networkpacket.source_ip_address() == self.init_source_ip and
                networkpacket.source_port() == self.init_source_port and
                networkpacket.destination_ip_address() == self.init_destination_ip and
                networkpacket.destination_port() == self.init_destination_port):
            return True
        elif (networkpacket.source_ip_address() == self.init_destination_ip and
              networkpacket.source_port() == self.init_destination_port and
              networkpacket.destination_ip_address() == self.init_source_ip and
              networkpacket.destination_port() == self.init_source_port):
            return True
        else:
            return False
