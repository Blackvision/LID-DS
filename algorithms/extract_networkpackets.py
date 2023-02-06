import os
from pprint import pprint

from algorithms.decision_engines.ae import AE
from algorithms.features.impl_networkpacket.flow_features import FlowFeatures
from algorithms.features.impl_networkpacket.min_max_scaling_net import MinMaxScalingNet
from algorithms.ids import IDS
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction


def main():
    ### feature config:
    #general
    # lid_ds_base_path = "/home/aohlhaeuser/Projekte/Masterarbeit"
    lid_ds_base_path = "/media/sf_VM_ubuntu-20-04-3-LTS"
    # result_path = "/home/aohlhaeuser/Projekte/Masterarbeit/Results/"
    result_path = "/media/sf_VM_ubuntu-20-04-3-LTS/Results/lokal/"
    datapacket_mode = DatapacketMode.NETWORKPACKET
    direction = Direction.OPEN
    time_window = 5000000000
    time_window_steps = 1000000000

    # Networkpacket:
    ngram_length_net = 1
    w2v_vector_size_net = 10            # 5 * 7 = 35     5
    w2v_window_size_net = 10            # 3, 5, 10       10
    thread_aware_net = False

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
        resulting_building_block_sys = None

        # features networkpackets
        if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
            #concatFeatures = ConcatFeatures()
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
        ids.detect()
        print("Ready")

        # print results
        print(f"Results for scenario: {scenario_range[scenario_number]}")
        results = ids.performance.get_results()
        pprint(results)


if __name__ == '__main__':
    main()
