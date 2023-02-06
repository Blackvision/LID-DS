import argparse
import logging
import os
import traceback
import time
import datetime
from pprint import pprint

from algorithms.data_preprocessor import DataPreprocessor
from algorithms.decision_engines.ae import AE
from algorithms.features.impl_networkpacket.concat_features import ConcatFeatures
from algorithms.features.impl_networkpacket.extract_features import ExtractFeatures
from algorithms.features.impl_networkpacket.flow_features import FlowFeatures
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
    direction = Direction.OPEN
    time_window = 5000000000
    time_window_steps = 1000000000

    dataloader = dataloader_factory(lid_ds_base_path + scenario, direction=direction)
    resulting_building_block_sys = None

    # features networkpackets
    if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
        # concatFeatures = ConcatFeatures()
        flowFeatures = FlowFeatures()
        minMaxScalingNet = MinMaxScalingNet(flowFeatures)
        ae_net = AE(input_vector=minMaxScalingNet)
        resulting_building_block_net = ae_net
    else:
        resulting_building_block_net = None

    ids = IDS(data_loader=dataloader,
              resulting_building_block_sys=resulting_building_block_sys,
              resulting_building_block_net=resulting_building_block_net,
              create_alarms=False,
              plot_switch=False,
              datapacket_mode=datapacket_mode,
              time_window=time_window,
              time_window_steps=time_window_steps)

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

    # write results
    date_today = str(datetime.date.today())
    if not os.path.exists(result_path + date_today):
        os.makedirs(result_path + date_today)
    filename = scenario + "_" + date_today + ".txt"
    f = open(result_path + date_today + "/" + filename, "a")
    f.write(str(datetime.datetime.now()) + " - " + str(datapacket_mode.value) + "\n")
    results = ids.performance.get_results()
    for k in sorted(results.keys()):
        f.write("'%s':'%s', \n" % (k, results[k]))
    f.write("\n\n")
    f.close()

    # print results
    print(f"Results for scenario: {scenario}")
    pprint(results)

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
