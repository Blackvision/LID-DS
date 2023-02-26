import argparse
import datetime
import logging
import os
import time
import traceback
from pprint import pprint

from algorithms.decision_engines.ae import AE
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl_syscall.int_embedding import IntEmbedding
from algorithms.features.impl_syscall.ngram import Ngram
from algorithms.features.impl_syscall.one_hot_encoding import OneHotEncoding
from algorithms.features.impl_syscall.syscall_name import SyscallName
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction


def main(args_scenario, args_base_path, args_result_path, args_ngram_length):
    ### feature config:
    # general
    scenario = args_scenario
    lid_ds_base_path = args_base_path
    result_path = args_result_path
    datapacket_mode = DatapacketMode.SYSCALL
    direction = Direction.BOTH

    # Syscall:
    ngram_length_sys = int(args_ngram_length)
    thread_aware_sys = True

    dataloader = dataloader_factory(lid_ds_base_path + scenario, direction=direction)
    resulting_building_block_net = None

    # features syscalls
    if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.BOTH:
        syscallname = SyscallName()
        int_encoding_sys = IntEmbedding(syscallname)
        ohe_sys = OneHotEncoding(int_encoding_sys)
        ngram_sys = Ngram(feature_list=[ohe_sys],
                          thread_aware=thread_aware_sys,
                          ngram_length=ngram_length_sys)
        # stide = Stide(input=ngram_sys, window_length=1000)
        ae_sys = AE(input_vector=ngram_sys, max_training_time=14400)
        resulting_building_block_sys = ae_sys
    else:
        resulting_building_block_sys = None

    ids = IDS(data_loader=dataloader,
              resulting_building_block_sys=resulting_building_block_sys,
              resulting_building_block_net=resulting_building_block_net,
              create_alarms=False,
              plot_switch=False,
              datapacket_mode=datapacket_mode,
              time_window=None,
              time_window_steps=None)
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
    f.write("ngram length: " + str(ngram_length_sys) + "\n")
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
        parser.add_argument('-n', dest='ngram_length', action='store', type=str, required=True,
                            help='ngram length')

        args = parser.parse_args()
        print(f"Start with scenario {args.scenario}")

        main(args.scenario, args.base_path, args.result_path, args.ngram_length)

    except KeyError as e:
        print(traceback.format_exc())
        print('Experiment failed')
        logging.error('Failed for scenario: %s', args.scenario)
