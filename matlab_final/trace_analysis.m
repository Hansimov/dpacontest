% Due to the very long duration of an encryption operation on the smart-card
% (the AES has been coded in C and not in assembly language),
% the traces only cover the first round and the beginning of the second round of the AES.

clear; 
% close all;

[trace_avg, trace] = trace_average(1);