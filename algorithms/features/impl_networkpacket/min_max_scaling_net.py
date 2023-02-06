import math
import typing

from algorithms.building_block import BuildingBlock
from dataloader.datapacket import Datapacket

class Normalization():

    def __init__(self, value: int):
        self._min = value
        self._max = value
        self._diff = 0

    def update(self, current_value: int):
        if current_value < self._min:
            self._min = current_value
        if current_value > self._max:
            self._max = current_value

    def set_diff(self):
        self._diff = self._max - self._min
        if self._diff == 0:
            print(f"cant calculate MinMaxScaling - instead calculating identity function")

    def get_norm_value(self, value):
        if self._diff != 0:
            return (value - self._min) / self._diff
        else:
            return value

class MinMaxScalingNet(BuildingBlock):

    def __init__(self, bb_to_scale: BuildingBlock):
        """
        """
        super().__init__()
        self._bb_to_scale = bb_to_scale
        self._bb_id = self._bb_to_scale.get_id()
        self._normalization = []

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this feature
        """
        return [self._bb_to_scale]

    def train_on(self, datapacket: Datapacket):
        current_value = self._bb_to_scale.get_result(datapacket)
        if current_value is not None:
            if self._normalization:
                for i in range(len(current_value)):
                    self._normalization[i].update(current_value[i])
            else:
                for value in current_value:
                    self._normalization.append(Normalization(value))

    def val_on(self, datapacket: Datapacket):
        current_value = self._bb_to_scale.get_result(datapacket)
        if current_value is not None:
            if self._normalization:
                for i in range(len(current_value)):
                    self._normalization[i].update(current_value[i])
            else:
                for value in current_value:
                    self._normalization.append(Normalization(value))

    def fit(self):
        for i in range(len(self._normalization)):
            self._normalization[i].set_diff()

    def _calculate(self, datapacket: Datapacket):
        """
        """
        current_value = self._bb_to_scale.get_result(datapacket)
        norm_value = []
        if current_value is not None:
            for i in range(len(current_value)):
                norm_value.append(self._normalization[i].get_norm_value(current_value[i]))
            return tuple(norm_value)
        else:
            return None
