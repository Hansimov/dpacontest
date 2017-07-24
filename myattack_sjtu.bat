@echo off
attack_wrapper.exe -i 30 -k 0 -o ./results_sjtu/results_sjtu -d traces -x dpav4_rsm_index -e v4_RSM -t fifo
cd ./results_sjtu
compute_results results_sjtu
pause