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
python ids_ae_cluster.py -s $1 -b $2 -r $3
