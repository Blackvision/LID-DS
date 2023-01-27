from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class SourcePort(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate source port of networkpacket
        """
        if networkpacket.source_port() is not None:
            source_port = str(networkpacket.source_port())
        else:
            source_port = str(0).zfill(4)
        return source_port

    def depends_on(self):
        return []