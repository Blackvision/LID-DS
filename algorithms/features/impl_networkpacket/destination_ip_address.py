from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class DestinationIpAddress(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate destination ip adresses of networkpacket
        """
        return networkpacket.destination_ip_address()

    def depends_on(self):
        return []
