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

# TODO alarm and alarms

if __name__ == '__main__':
    # feature config:
    ngram_length = 7
    ngram_length_network = 1
    w2v_size = 5
    w2v_window_size = 10
    thread_aware_syscall = True
    thread_aware_network = False
    hidden_size = int(math.sqrt(ngram_length * w2v_size))

    # LID-DS dataset, choose from 0 - 1:
    lid_ds_version_number = 1
    lid_ds_version = [
        "LID-DS-2019_Datensatz",
        "LID-DS-2021_Datensatz",
        "LID-DS-2021_Datensatz_reduziert"
    ]
    # LID-DS scenario names, choose range from 0 - 14:
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
        syscallname = SyscallName()

        w2v = W2VEmbedding(word=syscallname,
                           vector_size=w2v_size,
                           window_size=w2v_window_size,
                           epochs=500
                           )
        ngram = Ngram(feature_list=[w2v],
                      thread_aware=thread_aware_syscall,
                      ngram_length=ngram_length
                      )

        ae = AE(
            input_vector=ngram,
            hidden_size=hidden_size
        )

        # features networkpackets
        concatFeatures = ConcatFeatures()

        w2v_networkpacket = W2VEmbedding(word=concatFeatures,
                                         vector_size=w2v_size,
                                         window_size=ngram_length_network,
                                         epochs=500,
                                         thread_aware=False
                                         )

        ngram_networkpacket = Ngram(feature_list=[w2v_networkpacket],
                                    thread_aware=thread_aware_network,
                                    ngram_length=ngram_length_network
                                    )

        ae_networkpacket = AE(
            input_vector=ngram_networkpacket,
            hidden_size=hidden_size
        )

        ids = IDS(data_loader=dataloader,
                  resulting_building_block=ae,
                  resulting_building_block_networkpacket=ae_networkpacket,
                  create_alarms=False,
                  plot_switch=True,
                  datapacket_mode=DatapacketMode.BOTH)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()
        # detection
        results_syscalls = ids.detect()
        results_networkpackets = ids.detect_networkpacket()

        print("Syscalls:")
        pprint(results_syscalls)
        print("Networkpackets:")
        pprint(results_networkpackets)
        # ids.draw_plot()
