@echo off
attack_wrapper.exe -i 10 -k 0 -o ./results_fudan/results_fudan -d traces -x dpav4_rsm_index -e v4_RSM -t fifo
cd ./results_fudan
compute_results results_fudan
pause