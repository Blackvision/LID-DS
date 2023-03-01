from algorithms.combination_units.boolean_operation import BooleanOperation
from algorithms.combination_units.combination_unit import CombinationUnit
from algorithms.performance_measurement_both_boolean import PerformanceBothBoolean
from algorithms.score_plot_both import ScorePlotBoth


class BooleanOperationDatapacketTrigger(CombinationUnit):

    def __init__(self, boolean_operation: BooleanOperation,
                 scenario_path,
                 plot_switch: bool = False):
        self._boolean_operation = boolean_operation
        self._performance = PerformanceBothBoolean()
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
        list_anomaly_scores = []
        if len(anomaly_scores_both) > 0:
            if self._boolean_operation == BooleanOperation.AND:
                anomaly_score_sys = True
                anomaly_score_net = True
            else:
                anomaly_score_sys = False
                anomaly_score_net = False
            for anomaly_score in anomaly_scores_both:
                if anomaly_score[2] == 'sys':
                    anomaly_score_sys = anomaly_score[0]
                elif anomaly_score[2] == 'net':
                    anomaly_score_net = anomaly_score[0]

                if self._boolean_operation == BooleanOperation.AND:
                    if (anomaly_score_sys and anomaly_score_net):
                        anomaly_score_both = True
                    else:
                        anomaly_score_both = False
                elif self._boolean_operation == BooleanOperation.OR:
                    if (anomaly_score_sys or anomaly_score_net):
                        anomaly_score_both = True
                    else:
                        anomaly_score_both = False
                list_anomaly_scores.append((anomaly_score[1], anomaly_score[1], anomaly_score_both))
        return list_anomaly_scores
