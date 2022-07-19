from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class SourceIpAddress(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate source ip adresses of networkpacket
        """
        return networkpacket.source_ip_address()

    def depends_on(self):
        return []
