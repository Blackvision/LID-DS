from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class DestinationPort(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate destination port of networkpacket
        """
        if networkpacket.destination_port() is not None:
            destination_port = str(networkpacket.destination_port())
        else:
            destination_port = str(0).zfill(4)
        return destination_port

    def depends_on(self):
        return []