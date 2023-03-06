import datetime
import os
from pprint import pprint

from tqdm import tqdm

from algorithms.building_block import BuildingBlock
from algorithms.combination_units.combination_unit import CombinationUnit
from algorithms.data_preprocessor import DataPreprocessor
from algorithms.features.impl_networkpacket.flow_features import FlowFeatures
from algorithms.features.impl_networkpacket.flow_features_one import FlowFeaturesOne
from algorithms.features.impl_networkpacket.flow_features_three import FlowFeaturesThree
from algorithms.features.impl_networkpacket.flow_features_two import FlowFeaturesTwo
from algorithms.performance_measurement import Performance
from algorithms.score_plot import ScorePlot
from dataloader.base_data_loader import BaseDataLoader
from dataloader.datapacket_mode import DatapacketMode


class IDS:
    def __init__(self,
                 data_loader: BaseDataLoader,
                 resulting_building_block_sys: BuildingBlock = None,
                 resulting_building_block_net: BuildingBlock = None,
                 combination_unit: CombinationUnit = None,
                 plot_switch: bool = False,
                 create_alarms: bool = False,
                 datapacket_mode: DatapacketMode = DatapacketMode.SYSCALL,
                 scenario=None):
        self._data_loader = data_loader
        self._final_bb_sys = resulting_building_block_sys
        self._final_bb_net = resulting_building_block_net
        self._combination_unit = combination_unit
        self._create_alarms = create_alarms
        self._datapacket_mode = datapacket_mode
        self._scenario = scenario
        self._date_today = str(datetime.date.today())
        if self._datapacket_mode == DatapacketMode.SYSCALL or self._datapacket_mode == DatapacketMode.NETWORKPACKET:
            self.performance = Performance(create_alarms)
            if plot_switch is True:
                self.plot = ScorePlot(data_loader.scenario_path)
            else:
                self.plot = None
        elif self._datapacket_mode == DatapacketMode.BOTH:
            self.threshold_sys = 0.0
            self.threshold_net = 0.0
            self.performance = None
            self.plot = None
        else:
            self.performance = None
            self.plot = None
        self._data_preprocessor = DataPreprocessor(self._data_loader, self._final_bb_sys, self._final_bb_net,
                                                   self._datapacket_mode)

    def get_config_syscall(self) -> str:
        return self._data_preprocessor.get_graph_dot_syscall()

    def get_config_networkpacket(self) -> str:
        return self._data_preprocessor.get_graph_dot_networkpacket()

    def print_results(self):
        if self._datapacket_mode == DatapacketMode.BOTH:
            self.performance = self._combination_unit.get_performance()
        print(f"Results for scenario: {self._scenario}")
        pprint(self.performance.get_results())

    def save_results(self, result_path):
        if self._datapacket_mode == DatapacketMode.BOTH:
            self.performance = self._combination_unit.get_performance()
        if not os.path.exists(result_path + self._date_today):
            os.makedirs(result_path + self._date_today)
        filename = self._scenario + "_" + self._date_today + ".txt"
        f = open(result_path + self._date_today + "/" + filename, "a")
        f.write(str(datetime.datetime.now()) + " - " + str(self._datapacket_mode.value) + "\n")
        results = self.performance.get_results()
        for k in sorted(results.keys()):
            f.write("'%s':'%s', \n" % (k, results[k]))
        f.write("\n\n")
        f.close()

    def save_plot(self, result_path=None):
        # save data if wanted
        if self._datapacket_mode == DatapacketMode.BOTH:
            self.plot = self._combination_unit.get_plot()
        if self.plot is not None:
            plot_path = result_path + self._date_today + "/plots/"
            if not os.path.exists(plot_path):
                os.makedirs(plot_path)
            filename = self._scenario + "_" + self._date_today + str(self._datapacket_mode.value) + "_plot"
            self.plot.feed_figure()
            self.plot.save_plot(plot_path + filename)

    def draw_plot(self, filename=None):
        # plot data if wanted
        if self._datapacket_mode == DatapacketMode.BOTH:
            self.plot = self._combination_unit.get_plot()
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
            self._determine_threshold_both_boolean()

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
                self._set_host_ip(recording, final_bb)
            for datapacket in datapackets:
                anomaly_score = final_bb.get_result(datapacket)
                if anomaly_score != None:
                    if anomaly_score > max_score:
                        max_score = anomaly_score
            self._data_preprocessor.new_recording(self._datapacket_mode)
        self.performance.set_threshold(max_score)
        if self.plot is not None:
            self.plot.threshold = max_score
        print(f"Threshold {self._datapacket_mode.value}={max_score:.3f}".rjust(27))

    def _determine_threshold_both_boolean(self):
        max_score_sys = 0.0
        max_score_net = 0.0
        data = self._data_loader.validation_data()
        description = 'Threshold calculation for syscalls and networkpackets'.rjust(27)
        for recording in tqdm(data, description, unit=" recording"):
            self._set_host_ip(recording, self._final_bb_net)
            for syscall in recording.syscalls():
                anomaly_score = self._final_bb_sys.get_result(syscall)
                if anomaly_score != None:
                    if anomaly_score > max_score_sys:
                        max_score_sys = anomaly_score
            self._data_preprocessor.new_recording(DatapacketMode.SYSCALL)
            for networkpacket in recording.packets():
                anomaly_score = self._final_bb_net.get_result(networkpacket)
                if anomaly_score != None:
                    if anomaly_score > max_score_net:
                        max_score_net = anomaly_score
            self._data_preprocessor.new_recording(DatapacketMode.NETWORKPACKET)
        self.threshold_sys = max_score_sys
        self.threshold_net = max_score_net
        print(f"threshold both sys={max_score_sys:.3f} net={max_score_net:.3f}".rjust(27))

    def detect(self):
        if self._datapacket_mode == DatapacketMode.SYSCALL:
            self._detect(self._final_bb_sys)
        elif self._datapacket_mode == DatapacketMode.NETWORKPACKET:
            self._detect(self._final_bb_net)
        elif self._datapacket_mode == DatapacketMode.BOTH:
            self._detect_both_boolean()

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

    def _detect_both_boolean(self):
        data = self._data_loader.test_data()
        description = "anomaly detection for syscalls and networkpackets"
        for recording in tqdm(data, description.rjust(27), unit=" recording"):
            self._combination_unit.new_recording(recording)
            list_anomaly_scores_sys = []
            list_anomaly_scores_net = []
            self._set_host_ip(recording, self._final_bb_net)
            for syscall in recording.syscalls():
                anomaly_score = self._final_bb_sys.get_result(syscall)
                if anomaly_score != None:
                    list_anomaly_scores_sys.append((self._check_anomaly_score(anomaly_score, self.threshold_sys),
                                                    syscall.timestamp_unix_in_ns(),
                                                    "sys"))
            self._data_preprocessor.new_recording(DatapacketMode.SYSCALL)
            for networkpacket in recording.packets():
                anomaly_score = self._final_bb_net.get_result(networkpacket)
                if anomaly_score != None:
                    list_anomaly_scores_net.append((self._check_anomaly_score(anomaly_score, self.threshold_net),
                                                    networkpacket.timestamp_unix_in_ns(),
                                                    "net"))
            self._data_preprocessor.new_recording(DatapacketMode.NETWORKPACKET)
            self.performance = self._combination_unit.detect(list_anomaly_scores_sys, list_anomaly_scores_net)
        return self.performance

    def _set_host_ip(self, recording, bb_net):
        for bb in bb_net.depends_on():
            if (isinstance(bb, FlowFeatures) or
                    isinstance(bb, FlowFeaturesOne) or
                    isinstance(bb, FlowFeaturesTwo) or
                    isinstance(bb, FlowFeaturesThree)):
                for entry in recording.metadata()["container"]:
                    if entry["role"] == "victim":
                        bb.set_host_ip(entry["ip"])
                        return
            elif bb.depends_on():
                self._set_host_ip(recording, bb)

    def _check_anomaly_score(self, anomaly_score, threshold):
        if anomaly_score > threshold:
            return True
        if anomaly_score <= threshold:
            return False
