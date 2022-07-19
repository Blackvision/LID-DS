from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class DestinationPort(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate destination port of networkpacket
        """
        return networkpacket.destination_port()

    def depends_on(self):
        return []