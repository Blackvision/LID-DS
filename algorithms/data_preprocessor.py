import urllib
from tqdm import tqdm
from algorithms.building_block import BuildingBlock

from algorithms.building_block_manager import BuildingBlockManager
from dataloader.base_data_loader import BaseDataLoader
from dataloader.datapacket_mode import DatapacketMode


def dot_to_str(dot):
    dot_str = dot.to_string()
    lines = dot_str.splitlines()
    result = ""
    for line in lines:
        if '" -> "' in line or "strict digraph  {" in line or line == "}":
            result += line + "\n"
    return result

class DataPreprocessor:
    """
        Receives DataLoader object, and a list of BuildingBlocks
        Training data, validation data and test data can than be returned as feature lists.

    """

    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block: BuildingBlock,
                 resulting_building_block_networkpacket: BuildingBlock,
                 datapacket_mode: DatapacketMode = DatapacketMode.SYSCALL
                 ):
        self._datapacket_mode = datapacket_mode
        self._data_loader = data_loader
        self._baseBB = BuildingBlock()
        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.BOTH:
            self._building_block_manager = BuildingBlockManager(resulting_building_block)
            self._graph_dot = dot_to_str(self._building_block_manager.to_dot())
            graph_url_encode = urllib.parse.quote(self._graph_dot)
            url = f"https://dreampuf.github.io/GraphvizOnline/#{graph_url_encode}"
            print("-------------------------------")
            print("Dependency Graph Visualisation (Syscall):")
            print(url)
            print("-------------------------------")
        else:
            self._graph_dot = None

        if self._datapacket_mode == DatapacketMode.NETWORKPACKET or self._datapacket_mode == DatapacketMode.BOTH:
            self._building_block_networkpacket_manager = BuildingBlockManager(resulting_building_block_networkpacket)
            self._graph_dot_networkpacket = dot_to_str(self._building_block_networkpacket_manager.to_dot())
            graph_url_encode_networkpacket = urllib.parse.quote(self._graph_dot_networkpacket)
            url_networkpacket = f"https://dreampuf.github.io/GraphvizOnline/#{graph_url_encode_networkpacket}"
            print("-------------------------------")
            print("Dependency Graph Visualisation (Networkpacket):")
            print(url_networkpacket)
            print("-------------------------------")
        else:
            self._graph_dot_networkpacket = None

        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.BOTH:
            self._prepare_and_fit_building_blocks()

        if self._datapacket_mode == DatapacketMode.NETWORKPACKET or self._datapacket_mode == DatapacketMode.BOTH:
            self._prepare_and_fit_building_blocks_networkpackets()

    def get_graph_dot(self):
        return self._graph_dot

    def get_graph_dot_networkpacket(self):
        return self._graph_dot_networkpacket

    def _train_on_needed(self, bb_gen: list) -> bool:        
        for bb in bb_gen:
            if bb.train_on.__func__ != self._baseBB.train_on.__func__:
                return True
        return False

    def _val_on_needed(self, bb_gen: list) -> bool:        
        for bb in bb_gen:
            if bb.val_on.__func__ != self._baseBB.val_on.__func__:
                return True
        return False

    def _fit_needed(self, bb_gen: list) -> bool:        
        for bb in bb_gen:
            if bb.fit.__func__ != self._baseBB.fit.__func__:
                return True
        return False

    def _prepare_and_fit_building_blocks(self):
        """
        preprocessing for building blocks
        - calls train on, val on and fit for each building block on the training data in the order given by the building block manager
        """
        num_generations = len(self._building_block_manager.building_block_generations)
        for current_generation in range(0, num_generations):
            # infos
            print(f"at generation: {current_generation + 1} of {num_generations}: {self._building_block_manager.building_block_generations[current_generation]}")

            # training
            if not self._train_on_needed(self._building_block_manager.building_block_generations[current_generation]):
                pass
            else:
                for recording in tqdm(self._data_loader.training_data(),
                                    f"train bb {current_generation + 1}/{num_generations}".rjust(27),
                                    unit=" recording"):
                    for syscall in recording.syscalls():                        
                        # calculate already fitted bbs
                        for previous_generation in range(0, current_generation):
                            for previous_bb in self._building_block_manager.building_block_generations[previous_generation]:                            
                                previous_bb.get_result(syscall)
                        # call train_on for current iteration bbs
                        for current_bb in self._building_block_manager.building_block_generations[current_generation]:
                            current_bb.train_on(syscall)
                    self.new_recording(DatapacketMode.SYSCALL)

            # validation
            if not self._val_on_needed(self._building_block_manager.building_block_generations[current_generation]):
                pass
            else:            
                for recording in tqdm(self._data_loader.validation_data(),
                                    f"val bb {current_generation + 1}/{num_generations}".rjust(27),
                                    unit=" recording"):
                    for syscall in recording.syscalls():                        
                        # calculate already fitted bbs
                        for previous_generation in range(0, current_generation):
                            for previous_bb in self._building_block_manager.building_block_generations[previous_generation]:                            
                                previous_bb.get_result(syscall)
                        # call val_on for current iteration bbs
                        for current_bb in self._building_block_manager.building_block_generations[current_generation]:
                            current_bb.val_on(syscall)
                    self.new_recording(DatapacketMode.SYSCALL)

            # fit current generation bbs
            if not self._fit_needed(self._building_block_manager.building_block_generations[current_generation]):
                pass
            else:            
                for current_bb in tqdm(self._building_block_manager.building_block_generations[current_generation],
                                            f"fitting bbs {current_generation + 1}/{num_generations}".rjust(27),
                                            unit=" bbs"):
                    current_bb.fit()

    def _prepare_and_fit_building_blocks_networkpackets(self):
        """
        preprocessing for networkpacket building blocks
        - calls train on, val on and fit for each building block on the training data in the order given by the networkpacket building block manager
        """
        num_generations = len(self._building_block_networkpacket_manager.building_block_generations)
        for current_generation in range(0, num_generations):
            # infos
            print(f"at generation: {current_generation + 1} of {num_generations}: {self._building_block_networkpacket_manager.building_block_generations[current_generation]}")

            # training
            if not self._train_on_needed(self._building_block_networkpacket_manager.building_block_generations[current_generation]):
                pass
            else:
                for recording in tqdm(self._data_loader.training_data(),
                                      f"train bb {current_generation + 1}/{num_generations}".rjust(27),
                                      unit=" recording"):
                    for networkpacket in recording.packets():
                        # calculate already fitted bbs
                        for previous_generation in range(0, current_generation):
                            for previous_bb in self._building_block_networkpacket_manager.building_block_generations[previous_generation]:
                                previous_bb.get_result(networkpacket)
                        # call train_on for current iteration bbs
                        for current_bb in self._building_block_networkpacket_manager.building_block_generations[current_generation]:
                            current_bb.train_on(networkpacket)
                    self.new_recording(DatapacketMode.NETWORKPACKET)

            # validation
            if not self._val_on_needed(self._building_block_networkpacket_manager.building_block_generations[current_generation]):
                pass
            else:
                for recording in tqdm(self._data_loader.validation_data(),
                                      f"val bb {current_generation + 1}/{num_generations}".rjust(27),
                                      unit=" recording"):
                    for networkpacket in recording.packets():
                        # calculate already fitted bbs
                        for previous_generation in range(0, current_generation):
                            for previous_bb in self._building_block_networkpacket_manager.building_block_generations[previous_generation]:
                                previous_bb.get_result(networkpacket)
                        # call val_on for current iteration bbs
                        for current_bb in self._building_block_networkpacket_manager.building_block_generations[current_generation]:
                            current_bb.val_on(networkpacket)
                    self.new_recording(DatapacketMode.NETWORKPACKET)

            # fit current generation bbs
            if not self._fit_needed(self._building_block_networkpacket_manager.building_block_generations[current_generation]):
                pass
            else:
                for current_bb in tqdm(self._building_block_networkpacket_manager.building_block_generations[current_generation],
                                       f"fitting bbs {current_generation + 1}/{num_generations}".rjust(27),
                                       unit=" bbs"):
                    current_bb.fit()

    def new_recording(self, datapacket_mode: DatapacketMode = DatapacketMode.SYSCALL):
        """
        - this method should be called each time after a recording is done and a new recording starts
        - it iterates over all bbs and calls new_recording on them
        """
        if datapacket_mode == DatapacketMode.SYSCALL:
            for generation in self._building_block_manager.building_block_generations:
                for bb in generation:
                    bb.new_recording()
        elif datapacket_mode == DatapacketMode.NETWORKPACKET:
            for generation in self._building_block_networkpacket_manager.building_block_generations:
                for bb in generation:
                    bb.new_recording()
