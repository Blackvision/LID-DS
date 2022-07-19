from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class SourcePort(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate source port of networkpacket
        """
        return networkpacket.source_port()

    def depends_on(self):
        return []