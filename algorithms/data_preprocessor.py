import urllib

from tqdm import tqdm

from algorithms.building_block import BuildingBlock
from algorithms.building_block_manager import BuildingBlockManager
from algorithms.features.impl_networkpacket.flow_features import FlowFeatures
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
                 resulting_building_block_sys: BuildingBlock = None,
                 resulting_building_block_net: BuildingBlock = None,
                 datapacket_mode: DatapacketMode = DatapacketMode.SYSCALL
                 ):
        self._baseBB = BuildingBlock()
        self._datapacket_mode = datapacket_mode
        self._data_loader = data_loader

        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.BOTH:
            self._building_block_manager_sys = BuildingBlockManager(resulting_building_block_sys)
            self._graph_dot_sys = dot_to_str(self._building_block_manager_sys.to_dot())
            self._print_dependency_graph(self._graph_dot_sys, DatapacketMode.SYSCALL)
            self._prepare_and_fit_building_blocks(self._building_block_manager_sys, DatapacketMode.SYSCALL)
        else:
            self._building_block_manager_sys = None
            self._graph_dot_sys = None

        if self._datapacket_mode == DatapacketMode.NETWORKPACKET or self._datapacket_mode == DatapacketMode.BOTH:
            self._building_block_manager_net = BuildingBlockManager(resulting_building_block_net)
            self._graph_dot_net = dot_to_str(self._building_block_manager_net.to_dot())
            self._print_dependency_graph(self._graph_dot_net, DatapacketMode.NETWORKPACKET)
            self._prepare_and_fit_building_blocks(self._building_block_manager_net, DatapacketMode.NETWORKPACKET)
        else:
            self._building_block_manager_net = None
            self._graph_dot_net = None

    def get_graph_dot_syscall(self):
        return self._graph_dot_sys

    def get_graph_dot_networkpacket(self):
        return self._graph_dot_net

    def _print_dependency_graph(self, graph_dot, datapacket_mode: DatapacketMode):
        graph_url_encode = urllib.parse.quote(graph_dot)
        url = f"https://dreampuf.github.io/GraphvizOnline/#{graph_url_encode}"
        print("-------------------------------")
        print("Dependency Graph Visualisation " + str(datapacket_mode.value) + ":")
        print(url)
        print("-------------------------------")

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

    def _prepare_and_fit_building_blocks(self, building_block_manager: BuildingBlockManager, datapacket_mode: DatapacketMode):
        """
        preprocessing for building blocks
        - calls train on, val on and fit for each building block on the training data in the order given by the building block manager
        """
        num_generations = len(building_block_manager.building_block_generations)
        for current_generation in range(0, num_generations):
            # infos
            print(f"at generation: {current_generation + 1} of {num_generations}: {building_block_manager.building_block_generations[current_generation]}")

            # training
            if not self._train_on_needed(building_block_manager.building_block_generations[current_generation]):
                pass
            else:
                for recording in tqdm(self._data_loader.training_data(),
                                      f"train bb {current_generation + 1}/{num_generations}".rjust(27),
                                      unit=" recording"):
                    if datapacket_mode == DatapacketMode.SYSCALL:
                        datapackets = recording.syscalls()
                    elif datapacket_mode == DatapacketMode.NETWORKPACKET:
                        datapackets = recording.packets()
                        for building_block in building_block_manager.building_block_generations:
                            if isinstance(building_block[0], FlowFeatures):
                                for entry in recording.metadata()["container"]:
                                    if entry["role"] == "victim":
                                        building_block[0].set_host_ip(entry["ip"])
                    for datapacket in datapackets:
                        # calculate already fitted bbs
                        for previous_generation in range(0, current_generation):
                            for previous_bb in building_block_manager.building_block_generations[previous_generation]:
                                if datapacket_mode == DatapacketMode.SYSCALL:
                                    previous_bb.get_result(datapacket)
                                elif datapacket_mode == DatapacketMode.NETWORKPACKET:
                                    previous_bb.get_result(datapacket)
                        # call train_on for current iteration bbs
                        for current_bb in building_block_manager.building_block_generations[current_generation]:
                            if datapacket_mode == DatapacketMode.SYSCALL:
                                current_bb.train_on(datapacket)
                            elif datapacket_mode == DatapacketMode.NETWORKPACKET:
                                current_bb.train_on(datapacket)
                    if datapacket_mode == DatapacketMode.SYSCALL:
                        self.new_recording(DatapacketMode.SYSCALL)
                    elif datapacket_mode == DatapacketMode.NETWORKPACKET:
                        self.new_recording(DatapacketMode.NETWORKPACKET)

            # validation
            if not self._val_on_needed(building_block_manager.building_block_generations[current_generation]):
                pass
            else:            
                for recording in tqdm(self._data_loader.validation_data(),
                                      f"val bb {current_generation + 1}/{num_generations}".rjust(27),
                                      unit=" recording"):
                    if datapacket_mode == DatapacketMode.SYSCALL:
                        datapackets = recording.syscalls()
                    elif datapacket_mode == DatapacketMode.NETWORKPACKET:
                        datapackets = recording.packets()
                        for building_block in building_block_manager.building_block_generations:
                            if isinstance(building_block[0], FlowFeatures):
                                for entry in recording.metadata()["container"]:
                                    if entry["role"] == "victim":
                                        building_block[0].set_host_ip(entry["ip"])
                    for datapacket in datapackets:
                        # calculate already fitted bbs
                        for previous_generation in range(0, current_generation):
                            for previous_bb in building_block_manager.building_block_generations[previous_generation]:
                                if datapacket_mode == DatapacketMode.SYSCALL:
                                    previous_bb.get_result(datapacket)
                                elif datapacket_mode == DatapacketMode.NETWORKPACKET:
                                    previous_bb.get_result(datapacket)
                        # call val_on for current iteration bbs
                        for current_bb in building_block_manager.building_block_generations[current_generation]:
                            current_bb.val_on(datapacket)
                    if datapacket_mode == DatapacketMode.SYSCALL:
                        self.new_recording(DatapacketMode.SYSCALL)
                    elif datapacket_mode == DatapacketMode.NETWORKPACKET:
                        self.new_recording(DatapacketMode.NETWORKPACKET)

            # fit current generation bbs
            if not self._fit_needed(building_block_manager.building_block_generations[current_generation]):
                pass
            else:            
                for current_bb in tqdm(building_block_manager.building_block_generations[current_generation],
                                       f"fitting bbs {current_generation + 1}/{num_generations}".rjust(27),
                                       unit=" bbs"):
                    current_bb.fit()

    def new_recording(self, datapacket_mode: DatapacketMode = DatapacketMode.SYSCALL):
        """
        - this method should be called each time after a recording is done and a new recording starts
        - it iterates over all bbs and calls new_recording on them
        """
        if datapacket_mode == DatapacketMode.SYSCALL:
            for generation in self._building_block_manager_sys.building_block_generations:
                for bb in generation:
                    bb.new_recording()
        elif datapacket_mode == DatapacketMode.NETWORKPACKET:
            for generation in self._building_block_manager_net.building_block_generations:
                for bb in generation:
                    bb.new_recording()
