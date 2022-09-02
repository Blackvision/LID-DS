import math
from collections import deque

from algorithms.building_block import BuildingBlock
from algorithms.features.impl_syscall.threadID import ThreadID
from dataloader.datapacket import Datapacket
from dataloader.syscall import Syscall


class StreamSum(BuildingBlock):
    """
    gives the sum value from a stream of system call features
    """

    def __init__(self, feature: BuildingBlock, thread_aware: bool, window_length: int):
        """
        feature: the sum should be calculated on feature
        thread_aware: True or False
        window_length: length of the window considered
        """
        super().__init__()
        self._window_buffer = {}
        self._sum_values = {}
        self._feature = feature
        self._thread_aware = thread_aware
        self._window_length = window_length

        self._dependency_list = []
        self._dependency_list.append(feature)
        self._feature_id = feature.get_id()

    def depends_on(self):
        return self._dependency_list

    def _calculate(self, datapacket: Datapacket):
        """
        if window is full: returns the sum over feature in the window 
        if window is not full: None
        if current feature is None: None
        """
        new_value = self._feature.get_result(datapacket)
        if new_value is not None:
            thread_id = 0
            if self._thread_aware:
                thread_id = datapacket.thread_id()
            if thread_id not in self._window_buffer:
                self._window_buffer[thread_id] = deque(maxlen=self._window_length)
                self._sum_values[thread_id] = 0
            
            dropout_value = 0
            if len(self._window_buffer[thread_id]) == self._window_length:
                dropout_value = self._window_buffer[thread_id][0]
            self._window_buffer[thread_id].append(new_value)
            self._sum_values[thread_id] += new_value - dropout_value
            if len(self._window_buffer[thread_id]) == self._window_length:
                #print(f"  {thread_id} -> {self._sum_values[thread_id]} -> {self._window_buffer[thread_id]}")
                return self._sum_values[thread_id]
            else:
                return None
        else:
            return None

    def new_recording(self):
        """
        empty buffer so ngrams consist of same recording only
        """
        self._window_buffer = {}
        self._sum_values = {}
