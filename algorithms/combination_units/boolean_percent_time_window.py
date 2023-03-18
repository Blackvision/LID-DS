from algorithms.combination_units.combination_unit import CombinationUnit
from algorithms.performance_measurement_both_boolean import PerformanceBothBoolean
from algorithms.score_plot_both import ScorePlotBoth


class BooleanPercentTimeWindow(CombinationUnit):

    def __init__(self, time_window,
                 time_window_steps,
                 scenario_path,
                 plot_switch: bool = False):
        self._performance = PerformanceBothBoolean()
        self._time_window = time_window
        self._time_window_steps = time_window_steps
        if plot_switch is True:
            self._plot = ScorePlotBoth(scenario_path)
            self._plot.threshold = 0.5
        else:
            self._plot = None

    def get_performance(self):
        return self._performance

    def get_plot(self):
        return self._plot

    def new_recording(self, recording):
        self._performance.new_recording(recording)
        if self._plot is not None:
            self._plot.new_recording(recording)

    def detect(self, list_anomaly_scores_sys, list_anomaly_scores_net):
        if list_anomaly_scores_sys or list_anomaly_scores_net:
            list_anomaly_scores_both = self._merge_anomaly_score_lists(list_anomaly_scores_sys, list_anomaly_scores_net)
            anomaly_scores_both = self._calculate_anomaly_scores_both(list_anomaly_scores_both)
            for anomaly_score_window in anomaly_scores_both:
                self._performance.analyze_datapacket(anomaly_score_window[0],
                                                     anomaly_score_window[1],
                                                     anomaly_score_window[2])
                if self._plot is not None:
                    if anomaly_score_window[2]:
                        anomaly_score = 1.0
                    else:
                        anomaly_score = 0.0
                    self._plot.add_to_plot_data(anomaly_score,
                                                anomaly_score_window[1],
                                                self._performance.get_cfp_indices())
        return self._performance

    def _calculate_anomaly_scores_both(self, anomaly_scores_both):
        start_time_window = anomaly_scores_both[0][1]
        end_time_window = start_time_window + self._time_window
        timestamp_last_package = anomaly_scores_both[-1][1]
        list_anomaly_scores = []
        while end_time_window <= timestamp_last_package:
            window_length = 0
            count_true = 0
            count_false = 0
            while anomaly_scores_both[window_length][1] <= end_time_window:
                if anomaly_scores_both[window_length][0]:
                    count_true += 1
                elif not anomaly_scores_both[window_length][0]:
                    count_false += 1
                window_length += 1
            if window_length > 0:
                percent_of_true = count_true / window_length
                if percent_of_true >= 0.5:
                    anomaly_score = True
                else:
                    anomaly_score = False
                list_anomaly_scores.append((start_time_window, end_time_window, anomaly_score))
            start_time_window = start_time_window + self._time_window_steps
            end_time_window = end_time_window + self._time_window_steps
            while anomaly_scores_both[0][1] < start_time_window:
                anomaly_scores_both.remove(anomaly_scores_both[0])
        return list_anomaly_scores
