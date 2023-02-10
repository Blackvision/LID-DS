"""
script to start multiple jobs in cluster
"""
import os
import time

scenario_2021 = [
    "Bruteforce_CWE-307",
    "CVE-2012-2122",
    "CVE-2014-0160",
    "CVE-2017-12635_6",
    "CVE-2017-7529",
    "CVE-2018-3760",
    "CVE-2019-5418",
    "CVE-2020-13942",
    "CVE-2020-23839",
    "CVE-2020-9484",
    "CWE-89-SQL-injection",
    "EPS_CWE-434",
    "Juice-Shop",
    "PHP_CWE-434",
    "ZipSlip",
    # "real_world/"
]
SCENARIOS = scenario_2021
BASE_PATH = '/work/user/ak059mreo/LID-DS-2021_Datensatz/'
RESULT_PATH = '/work/user/ak059mreo/Results/'
USER = "ak059mreo"
SCRIPT = 'run_on_sc.sh'

MAX_JOBS_IN_QUEUE = 1000
NUM_EXPERIMENTS = 0
# NGRAM_LENGTHS = ["5", "7", "10", "13"]

def count_queue():
    """
    counts the number of my jobs in the queue
    """
    user = USER
    return int(os.popen(f"squeue -u {user} | wc -l").read().strip("\n")) - 1

def start_job(job_str):
    """
    starts the job given by str
    if the number of my jobs in the queue is smaller than MAX_JOBS_IN_QUEUE
    """
    while True:
        time.sleep(0.5)
        # get the number of jobs in the queue
        count = count_queue()
        print(f"there are {count} jobs in queue")
        if count < MAX_JOBS_IN_QUEUE:
            print(job_str)
            os.system(job_str)
            break

# start jobs for specific configuration
for scenario in SCENARIOS:
    NUM_EXPERIMENTS += 1
    command = f"sbatch --job-name=ex_{NUM_EXPERIMENTS:05} " + \
              f"{SCRIPT} " + \
              f"{scenario} " + \
              f"{BASE_PATH} " + \
              f"{RESULT_PATH} "
    start_job(command)

print(f"NUM_EXPERIMENTS = {NUM_EXPERIMENTS}")