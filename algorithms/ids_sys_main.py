import datetime
import os
import time
from pprint import pprint

from algorithms.decision_engines.stide import Stide
from algorithms.features.impl_syscall.int_embedding import IntEmbedding
from algorithms.features.impl_syscall.ngram import Ngram
from algorithms.features.impl_syscall.one_hot_encoding import OneHotEncoding
from algorithms.features.impl_syscall.syscall_name import SyscallName
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction


def main():
    ### feature config:
    # general
    # lid_ds_base_path = "/home/aohlhaeuser/Projekte/Masterarbeit"
    lid_ds_base_path = "/media/sf_VM_ubuntu-20-04-3-LTS"
    # result_path = "/home/aohlhaeuser/Projekte/Masterarbeit/Results/"
    result_path = "/media/sf_VM_ubuntu-20-04-3-LTS/Results/lokal/"
    plot_path = "/plots/"
    datapacket_mode = DatapacketMode.SYSCALL
    direction = Direction.OPEN
    draw_plot = True

    # Syscall:
    ngram_length_sys = 7  # 5, 7, 10, 13
    thread_aware_sys = True

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

        dataloader = dataloader_factory(scenario_path, direction=direction)
        resulting_building_block_net = None

        # features syscalls
        if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.BOTH:
            syscallname = SyscallName()
            int_encoding_sys = IntEmbedding(syscallname)
            ohe_sys = OneHotEncoding(int_encoding_sys)
            ngram_sys = Ngram(feature_list=[ohe_sys],
                              thread_aware=thread_aware_sys,
                              ngram_length=ngram_length_sys
                              )
            stide = Stide(ngram_sys)
            # ae_sys = AE(input_vector=ngram_sys)
            resulting_building_block_sys = stide
        else:
            resulting_building_block_sys = None

        ids = IDS(data_loader=dataloader,
                  resulting_building_block_sys=resulting_building_block_sys,
                  resulting_building_block_net=resulting_building_block_net,
                  create_alarms=False,
                  plot_switch=draw_plot,
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
            if not os.path.exists(result_path + date_today + plot_path):
                os.makedirs(result_path + date_today + plot_path)
            filename = scenario_range[scenario_number] + "_" + date_today + "_sys_plot"
            ids.save_plot(result_path + date_today + plot_path + filename)


if __name__ == '__main__':
    main()
