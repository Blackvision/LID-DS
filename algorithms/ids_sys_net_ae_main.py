import math
import os
import sys

from pprint import pprint
from algorithms.decision_engines.ae import AE
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.ngram import Ngram
from algorithms.features.impl.w2v_embedding import W2VEmbedding
from algorithms.features.impl_networkpacket.destination_ip_address import DestinationIpAddress
from algorithms.features.impl_networkpacket.destination_port import DestinationPort
from algorithms.features.impl_networkpacket.source_ip_address import SourceIpAddress
from algorithms.features.impl_networkpacket.source_port import SourcePort
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction

# TODO rename features impl to impl_syscall
# TODO alarm
# TODO alarms
# TODO score_plot

if __name__ == '__main__':
    # feature config:
    ngram_length = 7
    ngram_length_network = 1
    w2v_size = 5
    w2v_window_size = 10
    thread_aware = True
    thread_aware_false = False
    hidden_size = int(math.sqrt(ngram_length * w2v_size))

    # LID-DS dataset, choose from 0 - 1:
    lid_ds_version_number = 2
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
                      thread_aware=thread_aware,
                      ngram_length=ngram_length
                      )

        ae = AE(
            input_vector=ngram,
            hidden_size=hidden_size
        )

        sourceipaddress = SourceIpAddress()

        destinationipaddress = DestinationIpAddress()

        sourceport = SourcePort()

        destinationport = DestinationPort()

        networkpacketngram = Ngram(feature_list=[sourceipaddress, destinationipaddress, sourceport, destinationport],
                                    thread_aware=thread_aware_false,
                                    ngram_length=ngram_length_network
                                    )

        w2vX = W2VEmbedding(word=networkpacketngram,
                           vector_size=w2v_size,
                           window_size=ngram_length_network,
                           epochs=500,
                           thread_aware=False
                           )

        w2vXXXXX = W2VEmbedding(word=sourceipaddress,
                            vector_size=w2v_size,
                            window_size=ngram_length_network,
                            epochs=500,
                            thread_aware=False
                            )

        networkpacketngramX = Ngram(feature_list=[w2vXXXXX],
                                   thread_aware=thread_aware_false,
                                   ngram_length=ngram_length_network
                                   )

        aeX = AE(
            input_vector=networkpacketngramX,
            hidden_size=hidden_size
        )

        ids = IDS(data_loader=dataloader,
                  resulting_building_block=ae,
                  resulting_building_block_networkpacket=aeX,
                  create_alarms=False,
                  plot_switch=False,
                  datapacket_mode=DatapacketMode.BOTH)

        print("at evaluation:")
        # threshold
        ids.determine_threshold()
        # detection
        results = ids.detect()
        results_networkpacket = ids.detect_networkpacket()

        print("Syscalls:")
        pprint(results)
        print("Networkpackets:")
        pprint(results_networkpacket)

        # enrich results with configuration and save to disk
        # results['algorithm'] = "AE"
        # results['ngram_length'] = ngram_length
        # results['w2v_size'] = w2v_size
        # results['thread_aware'] = thread_aware
        # results['config'] = ids.get_config()
        # results['scenario'] = scenario_range[scenario_number]
        # result_path = 'results/results_ae.json'