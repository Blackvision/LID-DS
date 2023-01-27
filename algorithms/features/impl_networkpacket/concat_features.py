import ipaddress

from algorithms.building_block import BuildingBlock
from algorithms.features.impl_networkpacket.destination_ip_address import DestinationIpAddress
from algorithms.features.impl_networkpacket.destination_port import DestinationPort
from algorithms.features.impl_networkpacket.int_embedding_net import IntEmbeddingNet
from algorithms.features.impl_networkpacket.source_ip_address import SourceIpAddress
from algorithms.features.impl_networkpacket.source_port import SourcePort
from dataloader.networkpacket import Networkpacket


class ConcatFeatures(BuildingBlock):

    def __init__(self):
        super().__init__()
        self._source_ip_address_bb = SourceIpAddress()
        self._destination_ip_address_bb = DestinationIpAddress()
        self._source_port_bb = SourcePort()
        self._destination_port_bb = DestinationPort()
        self._dict_ip = {}
        self._dict_port = {}
        self._dependency_list = [self._source_ip_address_bb,
                                 self._destination_ip_address_bb,
                                 self._source_port_bb,
                                 self._destination_port_bb]


    def train_on(self, networkpacket: Networkpacket):
        source_ip_address = self._source_ip_address_bb.get_result(networkpacket)
        if source_ip_address not in self._dict_ip:
            self._dict_ip[source_ip_address] = len(self._dict_ip) + 1
        destination_ip_address = self._destination_ip_address_bb.get_result(networkpacket)
        if destination_ip_address not in self._dict_ip:
            self._dict_ip[destination_ip_address] = len(self._dict_ip) + 1

        source_port = self._source_port_bb.get_result(networkpacket)
        if source_port not in self._dict_port:
            self._dict_port[source_port] = len(self._dict_port) + 1
        destination_port = self._destination_port_bb.get_result(networkpacket)
        if destination_port not in self._dict_port:
            self._dict_port[destination_port] = len(self._dict_port) + 1


    def _calculate(self, networkpacket: Networkpacket):
        """
        calculate concatenated features of networkpacket
        """
        source_ip_address = self._source_ip_address_bb.get_result(networkpacket)
        try:
            source_ip_to_int = self._dict_ip[source_ip_address]
        except KeyError:
            source_ip_to_int = 0
        destination_ip_address = self._destination_ip_address_bb.get_result(networkpacket)
        try:
            destination_ip_to_int = self._dict_ip[destination_ip_address]
        except KeyError:
            destination_ip_to_int = 0

        source_port = self._source_port_bb.get_result(networkpacket)
        try:
            source_port_to_int = self._dict_port[source_port]
        except KeyError:
            source_port_to_int = 0
        destination_port = self._destination_port_bb.get_result(networkpacket)
        try:
            destination_port_to_int = self._dict_port[destination_port]
        except KeyError:
            destination_port_to_int = 0



        concatFeatures = source_ip_to_int + destination_ip_to_int + source_port_to_int + destination_port_to_int

        return concatFeatures

    def depends_on(self):
        return self._dependency_list