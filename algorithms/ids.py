from copy import deepcopy
from functools import reduce
from typing import Type

from tqdm import tqdm
from tqdm.contrib.concurrent import process_map

from algorithms.building_block import BuildingBlock
from algorithms.data_preprocessor import DataPreprocessor
from algorithms.features.impl_networkpacket.flow_features import FlowFeatures
from algorithms.performance_measurement import Performance
from algorithms.performance_measurement_both import PerformanceBoth
from algorithms.score_plot import ScorePlot
from dataloader.base_data_loader import BaseDataLoader
from dataloader.base_recording import BaseRecording
from dataloader.datapacket_mode import DatapacketMode


class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block_sys: BuildingBlock = None,
                 resulting_building_block_net: BuildingBlock = None,
                 plot_switch: bool = False,
                 create_alarms: bool = False,
                 datapacket_mode: DatapacketMode = DatapacketMode.SYSCALL,
                 time_window: int = None,
                 time_window_steps: int = None):
        self._data_loader = data_loader
        self._final_bb_sys = resulting_building_block_sys
        self._final_bb_net = resulting_building_block_net
        self._create_alarms = create_alarms
        self._datapacket_mode = datapacket_mode
        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.NETWORKPACKET:
            self.performance = Performance(create_alarms)
        elif self._datapacket_mode == DatapacketMode.BOTH:
            self.performance = PerformanceBoth(create_alarms)
        else:
            self.performance = None
        self.time_window = time_window
        self.time_window_steps = time_window_steps
        self.threshold = 0.0
        if plot_switch is True:
            self.plot = ScorePlot(data_loader.scenario_path)
        else:
            self.plot = None
        self._data_preprocessor = DataPreprocessor(self._data_loader, self._final_bb_sys, self._final_bb_net, self._datapacket_mode)

    def get_config_syscall(self) -> str:
        return self._data_preprocessor.get_graph_dot_syscall()

    def get_config_networkpacket(self) -> str:
        return self._data_preprocessor.get_graph_dot_networkpacket()

    def draw_plot(self, filename=None):
        # plot data if wanted
        if self.plot is not None:
            self.plot.feed_figure()
            self.plot.show_plot(filename)

    def determine_threshold(self):
        """
        decision engine calculates anomaly scores using validation data,
        saves biggest score as threshold for detection phase
        """
        if self._datapacket_mode == DatapacketMode.SYSCALL:
            self._determine_threshold(self._final_bb_sys)
        elif self._datapacket_mode == DatapacketMode.NETWORKPACKET:
            self._determine_threshold(self._final_bb_net)
        elif self._datapacket_mode == DatapacketMode.BOTH:
            self._determine_threshold_both()

    def _determine_threshold(self, final_bb: BuildingBlock):
        max_score = 0.0
        datapackets = None
        data = self._data_loader.validation_data()
        description = "Threshold calculation for " + str(self._datapacket_mode.value)
        for recording in tqdm(data, description.rjust(27), unit=" recording"):
            if self._datapacket_mode == DatapacketMode.SYSCALL:
                datapackets = recording.syscalls()
            elif self._datapacket_mode == DatapacketMode.NETWORKPACKET:
                datapackets = recording.packets()
                self._set_host_ip(recording,final_bb)
            for datapacket in datapackets:
                anomaly_score = final_bb.get_result(datapacket)
                if anomaly_score != None:                
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.new_recording(self._datapacket_mode)
        self.threshold = max_score
        self.performance.set_threshold(max_score)
        if self.plot is not None:
            self.plot.threshold = max_score
        print(f"Threshold {self._datapacket_mode.value}={max_score:.3f}".rjust(27))

    def _determine_threshold_both(self):
        max_score = 0.0
        data = self._data_loader.validation_data()
        description = 'Threshold calculation for syscalls and networkpackets'.rjust(27)
        for recording in tqdm(data, description, unit=" recording"):
            list_sys_anomaly_scores = []
            list_net_anomaly_scores = []
            self._set_host_ip(recording, self._final_bb_net)
            for syscall in recording.syscalls():
                anomaly_score = self._final_bb_sys.get_result(syscall)
                if anomaly_score != None:
                    sys = (anomaly_score, syscall.timestamp_unix_in_ns())
                    list_sys_anomaly_scores.append(sys)
            self._data_preprocessor.new_recording(DatapacketMode.SYSCALL)
            for networkpacket in recording.packets():
                anomaly_score = self._final_bb_net.get_result(networkpacket)
                if anomaly_score != None:
                    net = (anomaly_score, networkpacket.timestamp_unix_in_ns())
                    list_net_anomaly_scores.append(net)
            self._data_preprocessor.new_recording(DatapacketMode.NETWORKPACKET)
            if (len(list_sys_anomaly_scores) != 0) or (len(list_net_anomaly_scores) != 0):
                anomaly_scores_both = self._merge_anomaly_score_lists(list_sys_anomaly_scores, list_net_anomaly_scores)
                list_anomaly_scores = self._calculate_anomaly_scores_both(anomaly_scores_both)
                for anomaly_score in list_anomaly_scores:
                    if anomaly_score[2] > max_score:
                        max_score = anomaly_score[2]
        self.threshold_sys_and_net = max_score
        self.performance.set_threshold(max_score)
        print(f"threshold both (sys and net)={max_score:.3f}".rjust(27))

    def _set_host_ip(self, recording, bb_net):
        for bb in bb_net.depends_on():
            if isinstance(bb, FlowFeatures):
                for entry in recording.metadata()["container"]:
                    if entry["role"] == "victim":
                        bb.set_host_ip(entry["ip"])
                        return
            elif bb.depends_on():
                self._set_host_ip(recording, bb)

    def _merge_anomaly_score_lists(self, list_sys, list_net):
        merged_list = list_sys
        merged_list.extend(list_net)
        merged_list.sort(key=lambda elem: elem[1])
        return merged_list

    def _calculate_anomaly_scores_both(self, anomaly_scores_both):
        start_time_window = anomaly_scores_both[0][1]
        end_time_window = start_time_window + self.time_window
        timestamp_last_package = anomaly_scores_both[-1][1]
        list_anomaly_scores = []
        while end_time_window <= timestamp_last_package:
            window = []
            i = 0
            while anomaly_scores_both[i][1] <= end_time_window:
                window.append(anomaly_scores_both[i])
                i = i+1

            if len(window) > 0:
                sum_window = sum([anomaly_score[0] for anomaly_score in window])
                anomaly_score = sum_window / len(window)
                win = (start_time_window, end_time_window, anomaly_score)
                list_anomaly_scores.append(win)

            start_time_window = start_time_window + self.time_window_steps
            end_time_window = end_time_window + self.time_window_steps

            while anomaly_scores_both[0][1] < start_time_window:
                anomaly_scores_both.remove(anomaly_scores_both[0])

        return list_anomaly_scores

    def detect(self):
        if self._datapacket_mode == DatapacketMode.SYSCALL:
            self._detect(self._final_bb_sys)
        elif self._datapacket_mode == DatapacketMode.NETWORKPACKET:
            self._detect(self._final_bb_net)
        elif self._datapacket_mode == DatapacketMode.BOTH:
            self._detect_both()

    def _detect(self, final_bb: BuildingBlock) -> Performance:
        """
        detecting performance values using the test data,
        calling performance object for measurement and
        plot object if plot_switch is True
        """
        datapackets = None
        data = self._data_loader.test_data()
        description = "anomaly detection for " + str(self._datapacket_mode.value)
        for recording in tqdm(data, description.rjust(27), unit=" recording"):
            self.performance.new_recording(recording)
            if self.plot is not None:
                self.plot.new_recording(recording)
            if self._datapacket_mode == DatapacketMode.SYSCALL:
                datapackets = recording.syscalls()
            elif self._datapacket_mode == DatapacketMode.NETWORKPACKET:
                datapackets = recording.packets()
                self._set_host_ip(recording, final_bb)
            for datapacket in datapackets:
                anomaly_score = final_bb.get_result(datapacket)
                if anomaly_score != None:
                    self.performance.analyze_datapacket(datapacket, anomaly_score)
                    if self.plot is not None:
                        self.plot.add_to_plot_data(anomaly_score, datapacket, self.performance.get_cfp_indices())
            self._data_preprocessor.new_recording(self._datapacket_mode)
            # run end alarm once to ensure that last alarm gets saved
            if self.performance.alarms is not None:
                self.performance.alarms.end_alarm()
        return self.performance

    def _detect_both(self):
        data = self._data_loader.test_data()
        description = "anomaly detection for syscalls and networkpackets"
        for recording in tqdm(data, description.rjust(27), unit=" recording"):
            self.performance.new_recording(recording)
            if self.plot is not None:
                self.plot.new_recording(recording)
            list_sys_anomaly_scores = []
            list_net_anomaly_scores = []
            self._set_host_ip(recording, self._final_bb_net)
            for syscall in recording.syscalls():
                anomaly_score = self._final_bb_sys.get_result(syscall)
                if anomaly_score != None:
                    sys = (anomaly_score, syscall.timestamp_unix_in_ns())
                    list_sys_anomaly_scores.append(sys)
            self._data_preprocessor.new_recording(DatapacketMode.SYSCALL)
            for networkpacket in recording.packets():
                anomaly_score = self._final_bb_net.get_result(networkpacket)
                if anomaly_score != None:
                    net = (anomaly_score, networkpacket.timestamp_unix_in_ns())
                    list_net_anomaly_scores.append(net)
            self._data_preprocessor.new_recording(DatapacketMode.NETWORKPACKET)
            if (len(list_sys_anomaly_scores) != 0) or (len(list_net_anomaly_scores) != 0):
                anomaly_scores_both = self._merge_anomaly_score_lists(list_sys_anomaly_scores, list_net_anomaly_scores)
                list_anomaly_scores = self._calculate_anomaly_scores_both(anomaly_scores_both)
                for anomaly_score in list_anomaly_scores:
                    self.performance.analyze_datapacket(anomaly_score[0], anomaly_score[1], anomaly_score[2])
                    # TODO
                    # if self.plot is not None:
                        # self.plot.add_to_plot_data(anomaly_score[1], anomaly_score[0], self.performance.get_cfp_indices())
            if self.performance.alarms is not None:
                self.performance.alarms.end_alarm()
        return self.performance

    def detect_on_single_recording(self, recording: Type[BaseRecording]) -> Performance:
        """
        detecting performance values using single recording
        create Performance object and return it

        Args:
            recording: single recording to calculate performance on
        Returns:
            Performance: performance object
        """
        performance = Performance(self._create_alarms)
        performance.set_threshold(self.threshold)

        # Wenn das eine Exploit-Aufnahme ist, dann schreibe den Zeit-Stempel auf
        if recording.metadata()["exploit"]:
            performance.set_exploit_time(recording.metadata()["time"]["exploit"][0]["absolute"])
            performance._exploit_count += 1

        for syscall in recording.syscalls():
            anomaly_score = self._final_bb_sys.get_result(syscall)
            if anomaly_score != None:
                performance.analyze_datapacket(syscall, anomaly_score)

        self._data_preprocessor.new_recording(DatapacketMode.SYSCALL)
        performance.new_recording(recording)

        # run end alarm once to ensure that last alarm gets saved
        if performance.alarms is not None:
            performance.alarms.end_alarm()

        return performance

    def _calculate(recording_ids_tuple: tuple) -> Performance:
        """
            create deepcopy of IDS and get performance object for recording of container

            Args:
            recroding_ids_tuple:
                ids: IDS with which perfomance is calculated
                recording: Recording on which performance is calculated
        """
        # get ids (as deep copy) and recording
        ids = deepcopy(recording_ids_tuple[0])
        recording = recording_ids_tuple[1]
        # Calculate performance on current recording and return it
        return ids.detect_on_single_recording(recording)

    def detect_parallel(self) -> Performance:
        """
            map reduce for every recording
            map:    first calculate performances on each single recording with ids
            reduce: than sum up performances

            Returns:
                Performance: complete performance of all recordings

        """
        # creating list of Tuples with deepcopys of this ids object and recordings
        ids_and_recordings = [(self, recording) for recording in self._data_loader.test_data()]

        # parallel calculation for every recording
        performance_list = process_map(
            IDS._calculate, 
            ids_and_recordings, 
            chunksize = 20,
            desc="anomaly detection".rjust(27),
            unit=" recordings")

        # Sum up performances
        if self._create_alarms:
            final_performance = reduce(Performance.add_with_alarms, performance_list)
        else:
            final_performance = reduce(Performance.add, performance_list)
        
        return final_performance
