from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class Flow:
    def __init__(self, init_packet: Networkpacket):
        self.init_time = init_packet.timestamp_unix_in_ns()
        self.init_source_ip = init_packet.source_ip_address()
        self.init_destination_ip = init_packet.destination_ip_address()
        self.init_source_port = init_packet.source_port()
        self.init_destination_port = init_packet.destination_port()
        self.flow = []
        self.flow.append(init_packet)

    def add_packet(self, networkpacket: Networkpacket):
        self.flow.append(networkpacket)

    def get_last_packet_time(self):
        return self.flow[-1].timestamp_unix_in_ns()

    def belongs_to_flow(self, networkpacket: Networkpacket):
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

class FlowFeatures(BuildingBlock):

    def __init__(self):
        super().__init__()
        self._flows = []

    def train_on(self, networkpacket: Networkpacket):
        if self._flows:
            was_added = False
            for flow in self._flows:
                if flow.belongs_to_flow(networkpacket):
                    flow.add_packet(networkpacket)
                    was_added = True
            if not was_added:
                flow = Flow(networkpacket)
                self._flows.append(flow)
            return None
        else:
            flow = Flow(networkpacket)
            self._flows.append(flow)
            return None


    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate concatenated features of networkpacket
        """
        if self._flows:
            was_added = False
            for flow in self._flows:
                if flow.belongs_to_flow(networkpacket):
                    flow.add_packet(networkpacket)
                    was_added = True
            if not was_added:
                flow = Flow(networkpacket)
                self._flows.append(flow)
            return None
        else:
            flow = Flow(networkpacket)
            self._flows.append(flow)
            return None

    def depends_on(self):
        return []

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._flows = []