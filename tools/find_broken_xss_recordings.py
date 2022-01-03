import os
import zipfile

import json

from tqdm import tqdm

from dataloader.data_loader_2021 import DataLoader2021 as DataLoader

SCENARIO_NAMES = [
    "CVE-2020-23839"
]

def append_to_textfile(output_path: str, line: str, filename: str):
    """

    creates a text file for empty records if it does not exist yet
    then appends new lines to it

    """
    filepath = os.path.join(output_path, filename)
    if not os.path.exists(filepath):
        open(filepath, 'w+')

    with open(filepath, 'a') as textfile:
        textfile.write(line + '\n')

def find_in_sc():
    runs_folder = '/home/felix/repos/uni/work/LID-DS/scenarios/CVE-2020-23839/runs'

    files = os.listdir(runs_folder)

    for file in files:
        if file.endswith('.sc'):
            found = False

            rec_name = file[:-3]
            with open(os.path.join(runs_folder, file), 'r') as infile:
                lines = infile.readlines()
                for line in lines:
                    if 'passwd' in str(line):
                        found = True
                        break

            content = json.load(open(os.path.join(runs_folder, rec_name + '.json')))

            if len(content['container']) > 3:
                with_normal = True
            else:
                with_normal = False

            if not found:
                if not found:
                    if with_normal:
                        append_to_textfile('/home/felix/repos/uni/work/LID-DS/tools/defect_recordings/', rec_name,
                                           'normal_sc_broken.txt')
                    else:
                        append_to_textfile('/home/felix/repos/uni/work/LID-DS/tools/defect_recordings/', rec_name,
                                           'attack_only_sc_broken.txt')


def find_in_zip():
    # I/O
    dataset_base_path = '/media/felix/PortableSSD/rerecord/'

    # listings
    categories = ['test']
    subcategories = ['normal_and_attack']

    for scenario in tqdm(SCENARIO_NAMES):
        dataloader = DataLoader(os.path.join(dataset_base_path, scenario))
        for category in tqdm(categories):
            for recording in dataloader.extract_recordings(category):
                found = False
                recording_path = recording.path
                if not '/normal/' in recording_path:
                    sub_path = recording.path.replace(dataset_base_path, '')
                    src_zip = recording_path
                    recording_name = os.path.splitext(os.path.basename(os.path.normpath(recording_path)))[0]
                    scenario_name = sub_path.split('/')[0]


                    with zipfile.ZipFile(src_zip) as inzip:
                        for inzipinfo in inzip.infolist():
                            if inzipinfo.filename == f'{recording_name}.json':
                                with inzip.open(inzipinfo) as infile:
                                    content = json.loads(infile.read().decode('utf-8'))
                                    if len(content['container']) > 3:
                                        with_normal = True
                                    else:
                                        with_normal = False

                        # second determine timestamp
                        for inzipinfo in inzip.infolist():
                            if inzipinfo.filename == f'{recording_name}.sc':
                                with inzip.open(inzipinfo) as infile:
                                    lines = infile.readlines()
                                    for line in lines:
                                        if 'passwd' in str(line):
                                            found = True

                    if not found:
                        if with_normal:
                            append_to_textfile('/home/felix/repos/uni/work/LID-DS/tools/defect_recordings/', recording_name, 'normal_broken.txt')
                        else:
                            append_to_textfile('/home/felix/repos/uni/work/LID-DS/tools/defect_recordings/', recording_name, 'attack_only_broken.txt')



if __name__ == '__main__':
    find_in_zip()

