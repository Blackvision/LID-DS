from dataloader.networkpacket import Networkpacket
from dataloader.syscall import Syscall

from algorithms.building_block import BuildingBlock
from algorithms.features.impl_syscall.syscall_name import SyscallName


class IntEmbeddingNet(BuildingBlock):
    """
        convert system call name to unique integer
        
        Params:
        building_block: BB which should be embedded as int
    """

    # todo Kommentare anpassen

    def __init__(self):
        super().__init__()
        self._dict = {}

    def depends_on(self):
        return []

    def train_on(self, value):
        """
            takes one syscall and assigns integer
            integer is current length of syscall_dict
            keep 0 free for unknown syscalls
        """
        if value not in self._dict:
            self._dict[value] = len(self._dict) + 1

    def _calculate(self, value):
        """
            transforms given building_block to integer
        """
        try:
            value_to_int = self._dict[value]
        except KeyError:
            value_to_int = 0
        return value_to_int
