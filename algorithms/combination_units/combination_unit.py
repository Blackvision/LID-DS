class CombinationUnit:
    """
    base class for combining results from two detectors (sys and net)
    """

    def detect(self, list_sys_anomaly_scores, list_net_anomaly_scores):
        """
        combine the results from two detectors (sys and net)
        """
        raise NotImplementedError("each combination unit has to implement detect")

    def new_recording(self, recording):
        """
        empties buffer and prepares for next recording (sys and net)
        """
        raise NotImplementedError("each combination unit has to implement new_recording")

    def get_performance(self):
        """
        return the performance (sys and net)
        """
        raise NotImplementedError("each combination unit has to implement get_performance")

    def get_plot(self):
        """
        return the plot (sys and net)
        """
        raise NotImplementedError("each combination unit has to implement get_plot")

    def _merge_anomaly_score_lists(self, list_sys, list_net):
        merged_list = []
        merged_list.extend(list_sys)
        merged_list.extend(list_net)
        merged_list.sort(key=lambda elem: elem[1])
        return merged_list

    def _boolean_percent(self, count_true, count_all):
        percent_of_true = count_true / count_all
        if percent_of_true >= 0.5:
            return True
        else:
            return False
