from dataloader.data_loader_2019 import DataLoader
from dataloader.recording_2019 import RecordingDataParts
from dataloader.syscall import Direction

from pprint import pprint
from tqdm import tqdm


import json
import os


def save_to_json(results: dict, scenario_name: str):
    """

    saves results for one scenario to json file located at a given path
    overwrites old files

    """
    with open(os.path.join(scenario_name + '_syscall_stats.json'), 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)


def calc_return_value_stats(recording_list, description):
    normal_count = 0
    exploit_count = 0
    result_dict = {
        'normal': {
            'bytes_written' : 0,
            'bytes_read' : 0,
            'bytes_socket' : 0,
            'bytes_kernel' : 0
        },
        'exploit': {
            'bytes_written' : 0,
            'bytes_read' : 0,
            'bytes_socket' : 0,
            'bytes_kernel' : 0
        }
    }
    read = ['read', 'getdents']
    for recording in tqdm(recording_list, description, unit=" recordings", smoothing=0):
        if recording.recording_data_list[RecordingDataParts.IS_EXECUTING_EXPLOIT] == 'True':
            exploit_count += 1
            rec = 'exploit'
        else:
            normal_count += 1
            rec = 'normal'
        for syscall in recording.syscalls():
            return_value_string = syscall.param('res')
            if return_value_string:
                try:
                    return_value_int = int(return_value_string)
                    if return_value_int > 10 and return_value_int < 10000000000:
                        if 'write' in syscall.name():
                            result_dict[rec]['bytes_written'] += return_value_int
                        elif any(string in syscall.name() for string in read):
                            result_dict[rec]['bytes_read'] += return_value_int
                        elif 'send' in syscall.name():
                            result_dict[rec]['bytes_kernel'] += return_value_int
                        elif 'recv' in syscall.name():
                            result_dict[rec]['bytes_socket'] += return_value_int
                        elif 'clone' in syscall.name():
                            # returns threadID
                            continue
                        elif 'lseek' in syscall.name():
                            # returns file descriptor offset
                            continue
                        else:
                            continue
                            # print(syscall.name(), return_value_int)
                except Exception:
                    pass
    if exploit_count == 0:
        exploit_count = 1
    result_dict = {
        'normal': {
            'bytes_written' : int(result_dict['normal']['bytes_written']/normal_count),
            'bytes_read' : int(result_dict['normal']['bytes_read']/normal_count),
            'bytes_socket' : int(result_dict['normal']['bytes_socket']/normal_count),
            'bytes_kernel' : int(result_dict['normal']['bytes_kernel']/normal_count)
        },
        'exploit': {
            'bytes_written' : int(result_dict['exploit']['bytes_written']/exploit_count),
            'bytes_read' : int(result_dict['exploit']['bytes_read']/exploit_count),
            'bytes_socket' : int(result_dict['exploit']['bytes_socket']/exploit_count),
            'bytes_kernel' : int(result_dict['exploit']['bytes_kernel']/exploit_count)
        }
    }
    return result_dict


if __name__ == '__main__':

    SCENARIO_NAMES = [
        "Bruteforce_CWE-307",
        "CVE-2012-2122",
        "CVE-2014-0160",
        "CVE-2017-7529",
        "CVE-2018-3760",
        "CVE-2019-5418",
        "PHP_CWE-434",
    ]
    # iterates through list of all scenarios, main loop
    for scenario in SCENARIO_NAMES:
        # scenario = 'CVE-2017-7529'
        dataloader = DataLoader(f'../../Dataset_old/{scenario}/', Direction.CLOSE)
        result_dict = {}

        # dict to describe dataset structure
        data_parts = {
            'Training': dataloader.training_data(),
            'Validation': dataloader.validation_data(),
            'Test': dataloader.test_data()
        }
        for data_part in data_parts.keys():
            record_results = calc_return_value_stats(data_parts[data_part], f"{scenario}: {data_part}".rjust(45))
            if scenario not in result_dict.keys():
                result_dict[scenario] = {}
            result_dict[scenario][data_part] = record_results

        pprint(result_dict)
        save_to_json(result_dict, scenario)
