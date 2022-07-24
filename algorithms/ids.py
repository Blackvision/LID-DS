from tqdm import tqdm
from typing import Type

from copy import deepcopy
from tqdm.contrib.concurrent import process_map
from functools import reduce

from algorithms.building_block import BuildingBlock

from dataloader.base_recording import BaseRecording
from dataloader.base_data_loader import BaseDataLoader

from algorithms.score_plot import ScorePlot
from algorithms.data_preprocessor import DataPreprocessor 
from algorithms.performance_measurement import Performance
from dataloader.datapacket_mode import DatapacketMode

class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block_sys: BuildingBlock = None,
                 resulting_building_block_net: BuildingBlock = None,
                 plot_switch: bool = False,
                 create_alarms: bool = False,
                 datapacket_mode: DatapacketMode = DatapacketMode.SYSCALL):
        self._data_loader = data_loader
        self._datapacket_mode = datapacket_mode
        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.BOTH:
            self._final_bb_sys = resulting_building_block_sys
            self.performance_sys = Performance(create_alarms)
            if plot_switch is True:
                self.plot_sys = ScorePlot(data_loader.scenario_path)
            else:
                self.plot_sys = None
        else:
            self._final_bb_sys = None
            self.performance_sys = None

        if self._datapacket_mode == DatapacketMode.NETWORKPACKET or self._datapacket_mode == DatapacketMode.BOTH:
            self._final_bb_net = resulting_building_block_net
            self.performance_net= Performance(create_alarms)
            if plot_switch is True:
                self.plot_net = ScorePlot(data_loader.scenario_path)
            else:
                self.plot_net = None
        else:
            self._final_bb_net = None
            self.performance_net = None

        self._data_preprocessor = DataPreprocessor(self._data_loader, self._final_bb_sys, self._final_bb_net, self._datapacket_mode)
        self.threshold_sys = 0.0
        self.threshold_net = 0.0
        self.threshold_sys_and_net = 0.0
        self._create_alarms = create_alarms

    def get_config_syscall(self) -> str:
        return self._data_preprocessor.get_graph_dot_syscall()

    def get_config_networkpacket(self) -> str:
        return self._data_preprocessor.get_graph_dot_networkpacket()

    def determine_threshold(self):
        """
        decision engine calculates anomaly scores using validation data,
        saves biggest score as threshold for detection phase
        """
        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.BOTH:
            self._determine_threshold_syscall()

        if self._datapacket_mode == DatapacketMode.NETWORKPACKET or self._datapacket_mode == DatapacketMode.BOTH:
            self._determine_threshold_networkpacket()

        if self._datapacket_mode == DatapacketMode.BOTH:
            self._determine_threshold_both()

    def _determine_threshold_syscall(self):
        max_score = 0.0
        data = self._data_loader.validation_data()
        description = 'Threshold calculation for syscall'.rjust(27)
        for recording in tqdm(data, description, unit=" recording"):
            for syscall in recording.syscalls():                
                anomaly_score = self._final_bb_sys.get_result(syscall)
                if anomaly_score != None:                
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.new_recording(DatapacketMode.SYSCALL)
        self.threshold_sys = max_score
        self.performance_sys.set_threshold(max_score)
        if self.plot_sys is not None:
            self.plot_sys.threshold = max_score
        print(f"threshold syscall={max_score:.3f}".rjust(27))

    def _determine_threshold_networkpacket(self):
        max_score = 0.0
        data = self._data_loader.validation_data()
        description = 'Threshold calculation for networkpacket'.rjust(27)
        for recording in tqdm(data, description, unit=" recording"):
            for networkpacket in recording.packets():
                anomaly_score = self._final_bb_net.get_result(networkpacket)
                if anomaly_score != None:
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.new_recording(DatapacketMode.NETWORKPACKET)
        self.threshold_net = max_score
        self.performance_net.set_threshold(max_score)
        if self.plot_net is not None:
            self.plot_net.threshold = max_score
        print(f"threshold networkpacket={max_score:.3f}".rjust(27))

    def _determine_threshold_both(self):
        # TODO self._determine_threshold_both() adjusting the thresholds
        self.threshold_sys_and_net = self.threshold_sys + self.threshold_net
        print(f"threshold both (sys and net)={self.threshold_sys_and_net :.3f}".rjust(27))

    def detect(self):
        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.BOTH:
            self._detect_syscall()

        if self._datapacket_mode == DatapacketMode.NETWORKPACKET or self._datapacket_mode == DatapacketMode.BOTH:
            self._detect_networkpacket()

        if self._datapacket_mode == DatapacketMode.BOTH:
            self._detect_both()


    def _detect_syscall(self) -> Performance:
        """
        detecting performance values using the test data,
        calling performance object for measurement and
        plot object if plot_switch is True
        """
        data = self._data_loader.test_data()
        description = 'anomaly detection for syscall'.rjust(27)

        for recording in tqdm(data, description, unit=" recording"):
            self.performance_sys.new_recording(recording)
            if self.plot_sys is not None:
                self.plot_sys.new_recording(recording)

            for syscall in recording.syscalls():
                anomaly_score = self._final_bb_sys.get_result(syscall)
                if anomaly_score != None:
                    self.performance_sys.analyze_datapacket(syscall, anomaly_score)
                    if self.plot_sys is not None:
                        self.plot_sys.add_to_plot_data(anomaly_score, syscall, self.performance_sys.get_cfp_indices())

            self._data_preprocessor.new_recording(DatapacketMode.SYSCALL)

            # run end alarm once to ensure that last alarm gets saved
            if self.performance_sys.alarms is not None:
                self.performance_sys.alarms.end_alarm()
        return self.performance_sys

    def _detect_networkpacket(self) -> Performance:
        """
        detecting performance values using the test data,
        calling performance object for measurement and
        plot object if plot_switch is True
        """
        data = self._data_loader.test_data()
        description = 'anomaly detection for networkpacket'.rjust(27)

        for recording in tqdm(data, description, unit=" recording"):
            self.performance_net.new_recording(recording)
            if self.plot_net is not None:
                self.plot_net.new_recording(recording)

            for networkpacket in recording.packets():
                anomaly_score = self._final_bb_net.get_result(networkpacket)
                if anomaly_score != None:
                    self.performance_net.analyze_datapacket(networkpacket, anomaly_score)
                    if self.plot_net is not None:
                        self.plot_net.add_to_plot_data(anomaly_score, networkpacket, self.performance_net.get_cfp_indices())

            self._data_preprocessor.new_recording(DatapacketMode.NETWORKPACKET)

            # run end alarm once to ensure that last alarm gets saved
            if self.performance_net.alarms is not None:
                self.performance_net.alarms.end_alarm()
        return self.performance_net

    def _detect_both(self):
        #TODO self._detect_both()
        print("TODO self._detect_both()")

    def draw_plot(self, filename=None):
        # plot data if wanted
        if self.plot_sys is not None:
            self.plot_sys.feed_figure()
            self.plot_sys.show_plot(filename)
        if self.plot_net is not None:
            self.plot_net.feed_figure()
            self.plot_net.show_plot(filename)

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
        performance.set_threshold(self.threshold_sys)

        # Wenn das eine Exploit-Aufnahme ist, dann schreibe den Zeit-Stempel auf
        if recording.metadata()["exploit"]:
            performance.set_exploit_time(recording.metadata()["time"]["exploit"][0]["absolute"])
            performance._exploit_count += 1

        for syscall in recording.syscalls():
            anomaly_score = self._final_bb_sys.get_result(syscall)
            if anomaly_score != None:
                performance.analyze_datapacket(syscall, anomaly_score)

        self._data_preprocessor.new_recording()
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
