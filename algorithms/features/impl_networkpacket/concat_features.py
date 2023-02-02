from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class ConcatFeatures(BuildingBlock):

    def __init__(self):
        super().__init__()

    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate concatenated features of networkpacket
        """

        # internet_layer_protocol
        # source_ip_address
        # destination_ip_address
        # transport_layer_protocol
        # source_port
        # destination_port
        # highest_layer_protocol
        # land
        # layer_count
        # timestamp
        # length
        # transport_layer_checksum
        # transport_layer_checksum_status
        # (transport_layer_flags)
        # (data)

        concatFeatures = []
        concatFeatures.append(str(networkpacket.internet_layer_protocol()))
        concatFeatures.append(str(networkpacket.source_ip_address()))
        concatFeatures.append(str(networkpacket.destination_ip_address()))
        concatFeatures.append(str(networkpacket.transport_layer_protocol()))
        concatFeatures.append(str(networkpacket.source_port()))
        concatFeatures.append(str(networkpacket.destination_port()))
        concatFeatures.append(str(networkpacket.highest_layer_protocol()))
        concatFeatures.append(str(networkpacket.land()))
        concatFeatures.append(str(networkpacket.layer_count()))
        concatFeatures.append(str(networkpacket.timestamp_datetime()))
        concatFeatures.append(str(networkpacket.length()))
        concatFeatures.append(str(networkpacket.transport_layer_checksum()))
        concatFeatures.append(str(networkpacket.transport_layer_checksum_status()))

        # concatFeatures.append("ilp: " + str(networkpacket.internet_layer_protocol()))
        # concatFeatures.append("sia: " + str(networkpacket.source_ip_address()))
        # concatFeatures.append("dia: " + str(networkpacket.destination_ip_address()))
        # concatFeatures.append("tlp: " + str(networkpacket.transport_layer_protocol()))
        # concatFeatures.append("sp: " + str(networkpacket.source_port()))
        # concatFeatures.append("dp: " + str(networkpacket.destination_port()))
        # concatFeatures.append("hlp: " + str(networkpacket.highest_layer_protocol()))
        # concatFeatures.append("la: " + str(networkpacket.land()))
        # concatFeatures.append("lc: " + str(networkpacket.layer_count()))
        # concatFeatures.append("ti: " + str(networkpacket.timestamp_datetime()))
        # concatFeatures.append("le: " + str(networkpacket.length()))
        # concatFeatures.append("tlc: " + str(networkpacket.transport_layer_checksum()))
        # concatFeatures.append("tls: " + str(networkpacket.transport_layer_checksum_status()))

        return concatFeatures

    def depends_on(self):
        return []
