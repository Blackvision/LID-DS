import datetime
import os

from algorithms.building_block import BuildingBlock
from dataloader.networkpacket import Networkpacket


class ExtractFeatures(BuildingBlock):

    def __init__(self, input_vector: BuildingBlock, scenario, result_path):
        super().__init__()
        self._input_vector = input_vector
        self._dependency_list = [input_vector]
        self._input_size = 0
        self._training_set = set()
        self._validation_set = set()
        self._test_set = set()
        self._scenario = scenario
        self._result_path = result_path
        self._packet_count = 0
        self._source_ip_address_count = 0
        self._destination_ip_address_count = 0
        self._transport_layer_protocol_count = 0
        self._source_port_count = 0
        self._destination_port_count = 0
        self._highest_layer_protocol_count = 0
        self._land_count = 0
        self._dict = {}

    def train_on(self, networkpacket: Networkpacket):
        input_vector = self._input_vector.get_result(networkpacket)
        if input_vector is not None:
            if self._input_size == 0:
                self._input_size = len(input_vector)

            save = False
            self._packet_count = self._packet_count + 1

            if input_vector[1] == str(None):
                self._source_ip_address_count = self._source_ip_address_count + 1
                save = True
            if input_vector[2] == str(None):
                self._destination_ip_address_count = self._destination_ip_address_count + 1
                save = True
            if input_vector[3] == str(None):
                self._transport_layer_protocol_count = self._transport_layer_protocol_count + 1
                value = str(input_vector[6])
                if value not in self._dict:
                    self._dict[value] = len(self._dict) + 1
                save = True
            if input_vector[4] == str(None):
                self._source_port_count = self._source_port_count + 1
                save = True
            if input_vector[5] == str(None):
                self._destination_port_count = self._destination_port_count + 1
                save = True
            if input_vector[6] == str(None):
                self._highest_layer_protocol_count = self._highest_layer_protocol_count + 1
                save = True
            if input_vector[7] == str(1):
                self._land_count = self._land_count + 1
                save = True

            if save:
                date_today = str(datetime.date.today())
                if not os.path.exists(self._result_path + date_today):
                    os.makedirs(self._result_path + date_today)
                filename = self._scenario + "_" + date_today + ".txt"
                f = open(self._result_path + date_today + "/" + filename, "a")
                f.write("TR: " + str(input_vector) + "\n")
                f.close()

            self._training_set.add(tuple(input_vector))

    def val_on(self, networkpacket: Networkpacket):
        input_vector = self._input_vector.get_result(networkpacket)
        if input_vector is not None:
            save = False
            self._packet_count = self._packet_count + 1

            if input_vector[1] == str(None):
                self._source_ip_address_count = self._source_ip_address_count + 1
                save = True
            if input_vector[2] == str(None):
                self._destination_ip_address_count = self._destination_ip_address_count + 1
                save = True
            if input_vector[3] == str(None):
                self._transport_layer_protocol_count = self._transport_layer_protocol_count + 1
                value = str(input_vector[6])
                if value not in self._dict:
                    self._dict[value] = len(self._dict) + 1
                save = True
            if input_vector[4] == str(None):
                self._source_port_count = self._source_port_count + 1
                save = True
            if input_vector[5] == str(None):
                self._destination_port_count = self._destination_port_count + 1
                save = True
            if input_vector[6] == str(None):
                self._highest_layer_protocol_count = self._highest_layer_protocol_count + 1
                save = True
            if input_vector[7] == str(1):
                self._land_count = self._land_count + 1
                save = True

            if save:
                date_today = str(datetime.date.today())
                if not os.path.exists(self._result_path + date_today):
                    os.makedirs(self._result_path + date_today)
                filename = self._scenario + "_" + date_today + ".txt"
                f = open(self._result_path + date_today + "/" + filename, "a")
                f.write("VA: " + str(input_vector) + "\n")
                f.close()

            self._validation_set.add(tuple(input_vector))

    def _calculate(self, networkpacket: Networkpacket):
        input_vector = self._input_vector.get_result(networkpacket)
        if input_vector is not None:
            save = False
            self._packet_count = self._packet_count + 1

            if input_vector[1] == str(None):
                self._source_ip_address_count = self._source_ip_address_count + 1
                save = True
            if input_vector[2] == str(None):
                self._destination_ip_address_count = self._destination_ip_address_count + 1
                save = True
            if input_vector[3] == str(None):
                self._transport_layer_protocol_count = self._transport_layer_protocol_count + 1
                value = str(input_vector[6])
                if value not in self._dict:
                    self._dict[value] = len(self._dict) + 1
                save = True
            if input_vector[4] == str(None):
                self._source_port_count = self._source_port_count + 1
                save = True
            if input_vector[5] == str(None):
                self._destination_port_count = self._destination_port_count + 1
                save = True
            if input_vector[6] == str(None):
                self._highest_layer_protocol_count = self._highest_layer_protocol_count + 1
                save = True
            if input_vector[7] == str(1):
                self._land_count = self._land_count + 1
                save = True

            if save:
                date_today = str(datetime.date.today())
                if not os.path.exists(self._result_path + date_today):
                    os.makedirs(self._result_path + date_today)
                filename = self._scenario + "_" + date_today + ".txt"
                f = open(self._result_path + date_today + "/" + filename, "a")
                f.write("TS: " + str(input_vector) + "\n")
                f.close()

            self._test_set.add(tuple(input_vector))

    def print_result(self):
        date_today = str(datetime.date.today())
        if not os.path.exists(self._result_path + date_today):
            os.makedirs(self._result_path + date_today)
        filename = self._scenario + "_" + date_today + ".txt"
        f = open(self._result_path + date_today + "/" + filename, "a")
        result = "pc: " + str(self._packet_count) + ", sia: " + str(self._source_ip_address_count) + ", dia: " + str(self._destination_ip_address_count) + ", tlpc: " + str(self._transport_layer_protocol_count) + ", spc: " + str(self._source_port_count) + ", dpc: " + str(self._destination_port_count) + ", hlpc: " + str(self._highest_layer_protocol_count) + ", lc: " + str(self._land_count) + ", hlp: " + str(self._dict)
        f.write("TS: " + result + "\n")
        f.close()

    def depends_on(self):
        return self._dependency_list