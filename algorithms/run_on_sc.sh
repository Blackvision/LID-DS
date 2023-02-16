#!/bin/bash
#SBATCH --partition=paula
#SBATCH --time=20:00:00
#SBATCH --mem=64G

module load PyTorch/1.10.0-foss-2021a-CUDA-11.3.1
module load Wireshark/4.0.1-GCCcore-11.2.0
pip install --upgrade pip
pip install --user -e ../
pip install --user -r ../requirements.txt

# parameters:
# 1: -s  scenario
# 2: -b  base_path
# 3: -r  result_path
# 4: -n  ngram_length
# python ids_sys_main_cluster.py -s $1 -b $2 -r $3 -n $4
# python ids_net_main_cluster.py -s $1 -b $2 -r $3
# python ids_sys_net_main_cluster.py -s $1 -b $2 -r $3 -n $4
python  -m cProfile -o stats_ids_sys_net.prof ids_sys_net_main_cluster.py -s $1 -b $2 -r $3 -n $4
