import os

if __name__ == '__main__':
    with open('/home/felix/repos/uni/work/LID-DS/tools/defect_recordings/normal_sc_broken.txt', 'r') as infile:
        lines = infile.readlines()

        for line in lines:
            os.system(f'rm /home/felix/repos/uni/work/LID-DS/scenarios/CVE-2020-23839/runs/{line.strip()}.*')
