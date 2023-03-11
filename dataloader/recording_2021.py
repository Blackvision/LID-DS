import csv
import datetime
import json
import os
import traceback
import zipfile

import pcapkit

from dataloader.base_recording import BaseRecording
from dataloader.direction import Direction
from dataloader.networkpacket_2021 import Networkpacket2021
from dataloader.resource_statistic import ResourceStatistic
from dataloader.syscall_2021 import Syscall2021


class Recording2021(BaseRecording):
    """

        Single recording captured in 4 ways
        class provides functions to handle every type of recording
            --> syscall text file
            --> pcap packets
            --> json describing recording
            --> statistics of resources

        Args:
        path (str): path of recording
        name (str): name of file without extension

    """

    def __init__(self, path: str, name: str, direction: Direction):
        """

            Save name and path of recording.

            Parameter:
            path (str): path of associated files
            name (str): name without path and extension

        """
        self.path = path
        self.name = name
        self._direction = direction
        self.check_recording()

    def syscalls(self) -> str:
        """

            Prepare stream of syscalls,
            yield single lines

            Returns:
            str: syscall text line

        """
        try:
            with zipfile.ZipFile(self.path, 'r') as zipped:
                with zipped.open(self.name + '.sc') as unzipped:
                    for line_id, syscall in enumerate(unzipped, start=1):
                        syscall_object = Syscall2021(self.path, syscall.decode('utf-8').rstrip(), line_id=line_id)
                        if self._direction != Direction.BOTH:
                            if syscall_object.direction() == self._direction:
                                yield syscall_object
                        else:
                            yield syscall_object

        except Exception:
            raise Exception(f'Error while working with file: {self.name} at {self.path}')

    def packets(self):
        """

            Unzip and extract pcap objects
            pcap obj: pypcap Extractor object
            src:
                https://pypcapkit.jarryshaw.me/en/latest/foundation/extraction.html#pcapkit.foundation.extraction.Extractor

            Returns:
                Networkpacket2021

        """
        time = str(int(datetime.datetime.timestamp(datetime.datetime.now())*1000000))
        try:
            with zipfile.ZipFile(self.path, 'r') as zipped:
                file_list = zipped.namelist()
                for file in file_list:
                    if file.endswith('.pcap'):
                        path = os.path.join('tmp/', time)
                        os.mkdir(path)
                        zipped.extract(file, path)
                obj = pcapkit.extract(fin=f'tmp/{time}/{self.name}.pcap',
                                      engine='pyshark',
                                      store=True,
                                      nofile=True)
                for frame in obj.frame:
                    networkpacket_object = Networkpacket2021(self.path, frame)
                    yield networkpacket_object

        except Exception as e:
            print(f'Error extracting pcap file {self.name}. Exception stack trace:')
            print(traceback.format_exc())
            return None
        finally:
            os.remove(f'tmp/{time}/{self.name}.pcap')
            os.rmdir(f'tmp/{time}')

    def resource_stats(self) -> list:
        """

            Read .res file of recording.
            Includes usage of following resources for a point in time:
                timestamp,
                cpu_usage,
                memory_usage,
                network_received,
                network_send,
                storage_read,
                storage_written

            Returns:
            List of used resources

        """
        statistics = []
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.res') as unzipped:
                string = unzipped.read().decode('utf-8')
                reader = csv.reader(string.split('\n'), delimiter=',')
                # remove header
                next(reader)
                for row in reader:
                    if len(row) > 0:
                        statistics.append(ResourceStatistic(row))
        return statistics

    def metadata(self) -> dict:
        """

            Read json file and extract metadata as dict
            with following format:
            {"container": [
                    "ip": str,
                    "name": str,
                    "role": str
             "exploit": bool,
             "exploit_name": str,
             "image": str,
             "recording_time": int,
             "time":{
                    "container_ready": {
                        "absolute": float,
                        "source": str
                    },
                    "exploit": [
                        {
                            "absolute": float,
                            "name": str,
                            "source": str
                        }
                    ]
                    "warmup_end": {
                        "absolute": float,
                        "source": str
                    }
                }
            }

            Returns:
            dict: metadata dictionary

        """
        with zipfile.ZipFile(self.path, 'r') as zipped:
            with zipped.open(self.name + '.json') as unzipped:
                unzipped_byte_json = unzipped.read()
                unzipped_json = json.loads(unzipped_byte_json.decode('utf-8').replace("'", '"'))
        return unzipped_json

    def check_recording(self) -> bool:
        """

            check if zip file exists and if all necessary files are included

            Returns:
            bool: if check was succesfull

        """
        try:
            if not os.path.isfile(self.path):
                raise Exception(f'Missing .zip file for recording: {self.path}')
            with zipfile.ZipFile(self.path, 'r') as zipped:
                file_list = zipped.namelist()
                err_str = 'Recording Error: '
                if len(file_list) != 4:
                    if self.name + '.res' not in file_list:
                        res_err = 'Missing .res file '
                        err_str += res_err
                    if self.name + '.sc' not in file_list:
                        sc_err = 'Missing .sc file '
                        err_str += sc_err
                    if self.name + '.pcap' not in file_list:
                        pcap_err = 'Missing .pcap file '
                        err_str += pcap_err
                    if self.name + '.json' not in file_list:
                        json_err = 'Missing .json file '
                        err_str += json_err
                    if not os.path.isfile('missing_files.txt'):
                        with open('missing_files.txt', 'w+') as file:
                            file.write(err_str + f'in recording: {self.path}. \n')
                    else:
                        with open('missing_files.txt', 'a') as file:
                            file.write(err_str + f'in recording: {self.path}. \n')
                    print(f'{err_str}')
                    print('Have a look in missing_files.txt file')
        except Exception:
            print(f'Error with file {self.name} at {self.path}')
            if not os.path.isfile('missing_files.txt'):
                with open('missing_files.txt', 'w+') as file:
                    file.write(err_str + f'in recording: {self.path}. \n')
            else:
                with open('missing_files.txt', 'a') as file:
                    file.write(err_str + f'in recording: {self.path}. \n')
