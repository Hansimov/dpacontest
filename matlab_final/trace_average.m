function [trace_avg, trace] = trace_average(trace_number)

filename = cell(1,trace_number);
trace = cell(1,trace_number);

for i = 1:trace_number
    if i <= 10
        filename{i} = strcat('../traces/mytracetexts/tracetexts0000',int2str(i-1));
    else 
        filename{i} = strcat('../traces/mytracetexts/tracetexts000',int2str(i-1));
    end
    trace_tmp = importdata(filename{i});
    trace{i} = trace_tmp';
end

trace_sum = zeros(1,length(trace_tmp));
for i = 1:trace_number
    trace_sum = trace_sum + trace{i};
end

trace_avg = trace_sum/trace_number;

plot(trace_avg);
% hold on;
% plot(trace{3});
end

