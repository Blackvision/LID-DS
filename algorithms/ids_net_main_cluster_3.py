import argparse
import logging
import time
import traceback

import torch

from algorithms.decision_engines.ae import AE
from algorithms.features.impl_networkpacket.feature_set_3 import FeatureSetThree
from algorithms.features.impl_networkpacket.min_max_scaling_net import MinMaxScalingNet
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
    datapacket_mode = DatapacketMode.NETWORKPACKET
    direction = Direction.BOTH

    dataloader = dataloader_factory(lid_ds_base_path + scenario, direction=direction)
    resulting_building_block_sys = None
    combination_unit = None

    # features networkpackets
    if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
        flowFeatures = FeatureSetThree()
        minMaxScalingNet = MinMaxScalingNet(flowFeatures)
        ae_net = AE(input_vector=minMaxScalingNet, max_training_time=14400)
        resulting_building_block_net = ae_net
    else:
        resulting_building_block_net = None

    # Seeding
    torch.manual_seed(0)

    ids = IDS(data_loader=dataloader,
              resulting_building_block_sys=resulting_building_block_sys,
              resulting_building_block_net=resulting_building_block_net,
              combination_unit=combination_unit,
              create_alarms=False,
              plot_switch=False,
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
