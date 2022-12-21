import os
import time
import logging
import argparse
import traceback
import datetime

from pprint import pprint
from algorithms.decision_engines.ae import AE
from algorithms.features.impl_both.ngram import Ngram
from algorithms.features.impl_both.w2v_embedding import W2VEmbedding
from algorithms.features.impl_networkpacket.concat_features import ConcatFeatures
from algorithms.features.impl_syscall.one_hot_encoding import OneHotEncoding
from algorithms.features.impl_syscall.syscall_name import SyscallName
from algorithms.ids import IDS
from dataloader.datapacket_mode import DatapacketMode
from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction

def main(args_scenario, args_base_path, args_result_path):

    ### feature config:
    # general
    scenario = args_scenario
    lid_ds_base_path = args_base_path
    result_path = args_result_path
    datapacket_mode = DatapacketMode.SYSCALL
    direction = Direction.OPEN
    draw_plot = False

    # Syscall:
    ngram_length_sys = 7
    thread_aware_sys = True

    # Networkpacket:
    ngram_length_net = 7
    thread_aware_net = False

    # Both:
    time_window = 5000000000
    time_window_steps = 1000000000

    datapacket_modes = []
    if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.NETWORKPACKET:
        datapacket_modes = [datapacket_mode]
    elif datapacket_mode == DatapacketMode.BOTH:
        datapacket_modes = [datapacket_mode, DatapacketMode.SYSCALL, DatapacketMode.NETWORKPACKET]

    for datapacket_mode in datapacket_modes:
        dataloader = dataloader_factory(lid_ds_base_path + scenario, direction=direction)

        # features syscalls
        if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.BOTH:
            syscallname = SyscallName()
            ohe_sys = OneHotEncoding(syscallname)
            ngram_sys = Ngram(feature_list=[ohe_sys],
                              thread_aware=thread_aware_sys,
                              ngram_length=ngram_length_sys
                              )
            ae_sys = AE(input_vector=ngram_sys)
            resulting_building_block_sys = ae_sys
        else:
            resulting_building_block_sys = None

        # features networkpackets
        if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
            concatFeatures = ConcatFeatures()
            w2v_net = W2VEmbedding(word=concatFeatures,
                                   vector_size=10,
                                   window_size=10,
                                   epochs=500,
                                   thread_aware=False
                                   )
            # ohe_net = OneHotEncoding(concatFeatures)
            ngram_net = Ngram(feature_list=[w2v_net],
                              thread_aware=thread_aware_net,
                              ngram_length=ngram_length_net
                              )
            ae_net = AE(input_vector=ngram_net)
            resulting_building_block_net = ae_net
        else:
            resulting_building_block_net = None

        ids = IDS(data_loader=dataloader,
                  resulting_building_block_sys=resulting_building_block_sys,
                  resulting_building_block_net=resulting_building_block_net,
                  create_alarms=False,
                  plot_switch=draw_plot,
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

        if draw_plot:
            ids.draw_plot()


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
