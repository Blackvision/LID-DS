import os
import time

import torch

from algorithms.decision_engines.ae import AE
from algorithms.features.impl_networkpacket.feature_set_4 import FeatureSetFour
from algorithms.features.impl_networkpacket.min_max_scaling_net import MinMaxScalingNet
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
    datapacket_mode = DatapacketMode.NETWORKPACKET
    direction = Direction.BOTH
    draw_plot = False

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
        combination_unit = None

        # features networkpackets
        if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
            flowFeatures = FeatureSetFour()
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
                  plot_switch=draw_plot,
                  datapacket_mode=datapacket_mode,
                  scenario=scenario_range[scenario_number])

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

        # save plot
        ids.save_plot(result_path)


if __name__ == '__main__':
    main()
