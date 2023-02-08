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
    direction = Direction.OPEN

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
    scenario_range = scenario_names[0:14]

    protocols = {}

    for scenario_number in range(0, len(scenario_range)):
        scenario_path = os.path.join(lid_ds_base_path,
                                     lid_ds_version[lid_ds_version_number],
                                     scenario_range[scenario_number])

        dataloader = dataloader_factory(scenario_path, direction=direction)

        for recording in dataloader.training_data():
            datapackets = recording.packets()
            for datapacket in datapackets:
                # calculate already fitted bbs
                asdsf = datapacket.internet_layer_protocol()
                if asdsf not in protocols:
                    protocols[asdsf] = len(protocols) + 1
                qwert = datapacket.transport_layer_protocol()
                if qwert not in protocols:
                    protocols[qwert] = len(protocols) + 1
                hjkli = datapacket.highest_layer_protocol()
                if hjkli not in protocols:
                    protocols[hjkli] = len(protocols) + 1

        for recording in dataloader.validation_data():
            datapackets = recording.packets()
            for datapacket in datapackets:
                # calculate already fitted bbs
                asdsf = datapacket.internet_layer_protocol()
                if asdsf not in protocols:
                    protocols[asdsf] = len(protocols) + 1
                qwert = datapacket.transport_layer_protocol()
                if qwert not in protocols:
                    protocols[qwert] = len(protocols) + 1
                hjkli = datapacket.highest_layer_protocol()
                if hjkli not in protocols:
                    protocols[hjkli] = len(protocols) + 1

        for recording in dataloader.test_data():
            datapackets = recording.packets()
            for datapacket in datapackets:
                # calculate already fitted bbs
                asdsf = datapacket.internet_layer_protocol()
                if asdsf not in protocols:
                    protocols[asdsf] = len(protocols) + 1
                qwert = datapacket.transport_layer_protocol()
                if qwert not in protocols:
                    protocols[qwert] = len(protocols) + 1
                hjkli = datapacket.highest_layer_protocol()
                if hjkli not in protocols:
                    protocols[hjkli] = len(protocols) + 1
        print("asdf")

if __name__ == '__main__':
    main()
