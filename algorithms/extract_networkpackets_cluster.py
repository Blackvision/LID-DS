import argparse
import logging
import traceback

from algorithms.data_preprocessor import DataPreprocessor
from algorithms.features.impl_networkpacket.concat_features import ConcatFeatures
from algorithms.features.impl_networkpacket.extract_features import ExtractFeatures
from dataloader.dataloader_factory import dataloader_factory
from dataloader.datapacket_mode import DatapacketMode
from dataloader.direction import Direction


def main(args_scenario, args_base_path, args_result_path):

    ### feature config:
    # general
    scenario = args_scenario
    lid_ds_base_path = args_base_path
    result_path = args_result_path
    datapacket_mode = DatapacketMode.NETWORKPACKET
    direction = Direction.OPEN

    dataloader = dataloader_factory(lid_ds_base_path + scenario, direction=direction)

    # features networkpackets
    if datapacket_mode == DatapacketMode.NETWORKPACKET or datapacket_mode == DatapacketMode.BOTH:
        concatFeatures = ConcatFeatures()
        extractFeatures = ExtractFeatures(concatFeatures, scenario, result_path)
        resulting_building_block_net = extractFeatures
    else:
        resulting_building_block_net = None
    resulting_building_block_sys = None

    data_preprocessor = DataPreprocessor(dataloader, resulting_building_block_sys, resulting_building_block_net,
                                         datapacket_mode)

    print("testing")
    for recording in dataloader.test_data():
        for datapacket in recording.packets():
            resulting_building_block_net.get_result(datapacket)
        data_preprocessor.new_recording(datapacket_mode)

    resulting_building_block_net.print_result()

    print("ready")


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
