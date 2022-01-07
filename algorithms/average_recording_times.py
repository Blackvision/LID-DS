from dataloader.dataloader_factory import dataloader_factory
from dataloader.direction import Direction
import os
from tqdm import tqdm

data_base_path = "/home/eschulze/LID-DS-2021-no-relative-time"
scenarios = os.listdir(data_base_path)
time_interval_dict = {}
average_sum = 0
average_counter = 0


for scenario in scenarios:
    if scenario not in time_interval_dict:
        time_interval_dict[scenario] = {}
    scenario_path = os.path.join(data_base_path, scenario)
    dataloader = dataloader_factory(scenario_path, direction=Direction.CLOSE)
    data_types = [dataloader.validation_data(), dataloader.test_data(), dataloader.training_data()]

    previous_time = 0
    time_diff_list =[]
    irreg_syscalls = []

    for data in data_types:
        for recording in tqdm(data):
            recording_name = recording.name
            for syscall in recording.syscalls():
                if previous_time == 0:
                    previous_time = syscall.timestamp_unix_in_ns()
                else:
                    time_diff = syscall.timestamp_unix_in_ns() - previous_time
                    if time_diff > 0:
                        time_diff_list.append(time_diff)
                    #if time_diff < 0:
                    #    print(previous_time, time_diff, syscall.timestamp_unix_in_ns(), syscall.line_id, recording.name)
                    if time_diff < 0:
                        irreg_syscalls.append((scenario, recording_name, syscall.line_id))

                    previous_time = syscall.timestamp_unix_in_ns()

            previous_time = 0

        average_interval = (sum(time_diff_list) / len(time_diff_list)) * 10 ** -9
        average_sum += average_interval
        average_counter += 1
        max_interval = max(time_diff_list) * 10 ** -9
        min_interval = min(time_diff_list) * 10 ** -9

        time_interval_dict[scenario] = {"recording": recording.name,
                                        "average_interval": average_interval,
                                        "max_interval": max_interval,
                                        "min_interval": min_interval}
        print(time_interval_dict[scenario])

    print(time_interval_dict)
    print(f"total average time over all scenarios is {average_sum/average_counter}")
    print(irreg_syscalls)





