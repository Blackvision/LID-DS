import math
import os
import sys

from pprint import pprint
from algorithms.decision_engines.ae import AE
from algorithms.features.impl_networkpacket.concat_features import ConcatFeatures
from algorithms.features.impl_syscall.syscall_name import SyscallName
from algorithms.features.impl_both.ngram import Ngram
from algorithms.features.impl_both.w2v_embedding import W2VEmbedding
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction


if __name__ == '__main__':
    ### feature config:
    #general
    datapacket_mode = DatapacketMode.BOTH
    draw_plot = False

    # Syscall:
    ngram_length_sys = 7
    w2v_size_sys = 5
    w2v_window_size_sys = 10            # 3, 5, 10
    thread_aware_sys = True
    hidden_size_sys = int(math.sqrt(ngram_length_sys * w2v_size_sys))

    # Networkpacket:
    ngram_length_net = 1
    w2v_size_net = 5                    # 5 * 7 = 35
    w2v_window_size_net = 10            # 3, 5, 10
    thread_aware_net = False
    hidden_size_net = int(math.sqrt(ngram_length_net * w2v_size_net))

    # LID-DS dataset, choose from 0 - 2:
    lid_ds_version = [
        "LID-DS-2019_Datensatz",
        "LID-DS-2021_Datensatz",
        "LID-DS-2021_Datensatz_reduziert"
    ]
    lid_ds_version_number = 1

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

    # getting the LID-DS base path from argument or environment variable
    if len(sys.argv) > 1:
        lid_ds_base_path = sys.argv[1]
    else:
        try:
            lid_ds_base_path = "/media/sf_VM_ubuntu-20-04-3-LTS"
        except KeyError:
            raise ValueError("No LID-DS Base Path given. Please specify as argument or set Environment Variable "
                             "$LID_DS_BASE")

    for scenario_number in range(0, len(scenario_range)):
        scenario_path = os.path.join(lid_ds_base_path,
                                     lid_ds_version[lid_ds_version_number],
                                     scenario_range[scenario_number])

        dataloader = dataloader_factory(scenario_path, direction=Direction.OPEN)

        # features syscalls
        if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.BOTH:
            syscallname = SyscallName()
            w2v_sys = W2VEmbedding(word=syscallname,
                                   vector_size=w2v_size_sys,
                                   window_size=w2v_window_size_sys,
                                   epochs=500
                                   )
            ngram_sys = Ngram(feature_list=[w2v_sys],
                              thread_aware=thread_aware_sys,
                              ngram_length=ngram_length_sys
                              )
            ae_sys = AE(input_vector=ngram_sys,
                        hidden_size=hidden_size_sys
                        )
        else:
            ae_sys = None

        # features networkpackets
        if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
            concatFeatures = ConcatFeatures()
            w2v_net = W2VEmbedding(word=concatFeatures,
                                   vector_size=w2v_size_net,
                                   window_size=w2v_window_size_net,
                                   epochs=500,
                                   thread_aware=False
                                   )
            ngram_net = Ngram(feature_list=[w2v_net],
                              thread_aware=thread_aware_net,
                              ngram_length=ngram_length_net
                              )
            ae_net = AE(input_vector=ngram_net,
                        hidden_size=hidden_size_net
                        )
        else:
            ae_net = None

        ids = IDS(data_loader=dataloader,
                  resulting_building_block_sys=ae_sys,
                  resulting_building_block_net=ae_net,
                  create_alarms=False,
                  plot_switch=True,
                  datapacket_mode=datapacket_mode)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()

        # detection
        ids.detect()

        if datapacket_mode == DatapacketMode.SYSCALL or datapacket_mode == DatapacketMode.BOTH:
            print("Syscalls:")
            pprint(ids.performance_sys)
            # pprint(ids.performance_sys.get_results())

        if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
            print("Networkpackets:")
            pprint(ids.performance_net)
            # pprint(ids.performance_net.get_results())

        if draw_plot:
            ids.draw_plot()
