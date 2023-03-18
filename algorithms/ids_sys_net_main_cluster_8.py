import argparse
import logging
import time
import traceback

import torch

from algorithms.combination_units.boolean_operation import BooleanOperation
from algorithms.combination_units.boolean_operation_time_window import BooleanOperationTimeWindow
from algorithms.decision_engines.ae import AE
from algorithms.features.impl_networkpacket.feature_set_4 import FeatureSetFour
from algorithms.features.impl_networkpacket.min_max_scaling_net import MinMaxScalingNet
from algorithms.features.impl_syscall.int_embedding import IntEmbedding
from algorithms.features.impl_syscall.ngram import Ngram
from algorithms.features.impl_syscall.one_hot_encoding import OneHotEncoding
from algorithms.features.impl_syscall.syscall_name import SyscallName
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction


def main(args_scenario, args_base_path, args_result_path):
    ### feature config:
    # general
    scenario = args_scenario
    lid_ds_base_path = args_base_path
    result_path = args_result_path
    datapacket_mode = DatapacketMode.BOTH
    direction = Direction.BOTH
    draw_plot = False
    time_window = 1000000000
    time_window_steps = 1000000000

    # Syscall:
    ngram_length_sys = 5
    thread_aware_sys = True

    dataloader = dataloader_factory(lid_ds_base_path + scenario, direction=direction)

    # features syscalls
    if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.BOTH:
        syscallname = SyscallName()
        int_encoding_sys = IntEmbedding(syscallname)
        ohe_sys = OneHotEncoding(int_encoding_sys)
        ngram_sys = Ngram(feature_list=[ohe_sys],
                          thread_aware=thread_aware_sys,
                          ngram_length=ngram_length_sys)
        # stide = Stide(input=ngram_sys, window_length=1000)
        ae_sys = AE(input_vector=ngram_sys, max_training_time=172800)
        resulting_building_block_sys = ae_sys
    else:
        resulting_building_block_sys = None

    # features networkpackets
    if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
        flow_features = FeatureSetFour()
        min_max_scaling_net = MinMaxScalingNet(flow_features)
        ae_net = AE(input_vector=min_max_scaling_net, max_training_time=14400)
        resulting_building_block_net = ae_net
    else:
        resulting_building_block_net = None

    # config combination unit
    if datapacket_mode == DatapacketMode.BOTH:
        combination_unit = BooleanOperationTimeWindow(boolean_operation=BooleanOperation.OR,
                                                      time_window=time_window,
                                                      time_window_steps=time_window_steps,
                                                      scenario_path=dataloader.scenario_path,
                                                      plot_switch=draw_plot)
        # combination_unit = BooleanOperationDatapacketTrigger(boolean_operation=BooleanOperation.AND,
        #                                                      scenario_path=dataloader.scenario_path,
        #                                                      plot_switch=draw_plot)
    else:
        combination_unit = None

    # Seeding
    torch.manual_seed(0)

    ids = IDS(data_loader=dataloader,
              resulting_building_block_sys=resulting_building_block_sys,
              resulting_building_block_net=resulting_building_block_net,
              combination_unit=combination_unit,
              create_alarms=False,
              plot_switch=draw_plot,
              datapacket_mode=datapacket_mode,
              scenario=scenario)

    # threshold
    print("Determine threshold:")
    ids.determine_threshold()

    # detection
    print("Detection:")
    start = time.time()
    ids.detect()
    end = time.time()
    detection_time = (end - start) / 60  # in min
    print("Detection time: " + str(detection_time))

    # save and print results
    ids.save_results(result_path)
    ids.print_results()


if __name__ == '__main__':
    try:
        logging.basicConfig(filename='experiments.log', level=logging.WARNING)
        parser = argparse.ArgumentParser(description='Statistics for LID-DS 2021')

        parser.add_argument('-s', dest='scenario', action='store', type=str, required=True,
                            help='scenario name')
        parser.add_argument('-b', dest='base_path', action='store', type=str, required=True,
                            help='LID-DS base path')
        parser.add_argument('-r', dest='result_path', action='store', type=str, required=True,
                            help='result path')

        args = parser.parse_args()
        print(f"Start with scenario {args.scenario}")

        main(args.scenario, args.base_path, args.result_path)

    except KeyError as e:
        print(traceback.format_exc())
        print('Experiment failed')
        logging.error('Failed for scenario: %s', args.scenario)
