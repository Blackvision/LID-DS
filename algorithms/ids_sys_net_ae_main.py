import datetime
import os
import time
from pprint import pprint

from algorithms.decision_engines.ae import AE
from algorithms.features.impl_both.ngram import Ngram
from algorithms.features.impl_both.w2v_embedding import W2VEmbedding
from algorithms.features.impl_networkpacket.concat_features import ConcatFeatures
from algorithms.features.impl_networkpacket.concat_features_binary import ConcatFeaturesBinary
from algorithms.features.impl_networkpacket.concat_features_decimal import ConcatFeaturesDecimal
from algorithms.features.impl_syscall.int_embedding import IntEmbedding
from algorithms.features.impl_syscall.one_hot_encoding import OneHotEncoding
from algorithms.features.impl_syscall.syscall_name import SyscallName
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction


def main():
    ### feature config:
    #general
    lid_ds_base_path = "/media/sf_VM_ubuntu-20-04-3-LTS"
    result_path = "/media/sf_VM_ubuntu-20-04-3-LTS/Results/lokal/"
    datapacket_mode = DatapacketMode.NETWORKPACKET
    direction = Direction.OPEN
    draw_plot = False

    # Syscall:
    ngram_length_sys = 5   # 7
    thread_aware_sys = True

    # Networkpacket:
    ngram_length_net = 1
    w2v_vector_size_net = 10            # 5 * 7 = 35     5
    w2v_window_size_net = 10            # 3, 5, 10       10
    thread_aware_net = False

    # Both:
    time_window = 5000000000
    time_window_steps = 1000000000

    # LID-DS dataset, choose from 0 - 2:
    lid_ds_version = [
        "LID-DS-2019_Datensatz",
        "LID-DS-2021_Datensatz",
        "LID-DS-2021_Datensatz_reduziert"
    ]
    lid_ds_version_number = 2

    # LID-DS scenario names, choose range from 0 - 14 (scenario_names[1:2]):
    scenario_names = [
        "CVE-2017-7529",
        "CVE-2014-0160",
        "CVE-2012-2122",
        "Bruteforce_CWE-307",
        "CVE-2020-23839",
        "CWE-89-SQL-injection",
        "PHP_CWE-434",
        "ZipSlip",
        "CVE-2018-3760",
        "CVE-2020-9484",
        "EPS_CWE-434",
        "CVE-2019-5418",
        "Juice-Shop",
        "CVE-2020-13942",
        "CVE-2017-12635_6"
    ]
    scenario_range = scenario_names[1:2]

    for scenario_number in range(0, len(scenario_range)):
        scenario_path = os.path.join(lid_ds_base_path,
                                     lid_ds_version[lid_ds_version_number],
                                     scenario_range[scenario_number])

        datapacket_modes = []
        if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.NETWORKPACKET:
            datapacket_modes = [datapacket_mode]
        elif datapacket_mode == DatapacketMode.BOTH:
            datapacket_modes = [datapacket_mode, DatapacketMode.SYSCALL, DatapacketMode.NETWORKPACKET]

        for datapacket_mode in datapacket_modes:
            dataloader = dataloader_factory(scenario_path, direction=direction)

            # features syscalls
            if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.BOTH:
                syscallname = SyscallName()
                int_encoding_sys = IntEmbedding(syscallname)
                ohe_sys = OneHotEncoding(int_encoding_sys)
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
                concatFeatures = ConcatFeaturesDecimal()
                ngram_net = Ngram(feature_list=[concatFeatures],
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
            filename = scenario_range[scenario_number] + "_" + date_today + ".txt"
            f = open(result_path + date_today + "/" + filename, "a")
            f.write(str(datetime.datetime.now()) + " - " + str(datapacket_mode.value) + "\n")
            results = ids.performance.get_results()
            for k in sorted(results.keys()):
                f.write("'%s':'%s', \n" % (k, results[k]))
            f.write("\n\n")
            f.close()

            # print results
            print(f"Results for scenario: {scenario_range[scenario_number]}")
            pprint(results)

            if draw_plot:
                ids.draw_plot()

if __name__ == '__main__':
    main()
