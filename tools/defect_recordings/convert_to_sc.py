import os


if __name__ == '__main__':

    runs_folder = '/home/felix/repos/uni/work/LID-DS/scenarios/CVE-2020-23839/runs'

    files = os.listdir(runs_folder)

    for file in files:
        if file.endswith('.scap'):
            filename = file[:-5]
            os.system(
                f'sysdig -v -b -p "%evt.rawtime %user.uid %proc.pid %proc.name %thread.tid %syscall.type %evt.dir %evt.args" -r {runs_folder}/{file} "proc.pid != -1" > {runs_folder}/{filename}.sc')
