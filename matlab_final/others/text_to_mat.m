tic;
trace_num = 10000;
% trace = cell(trace_num,1);
% save('F:\Sources\MATLAB\work\dpatraces\trace.mat','trace','-v7.3');
trace_file = matfile('F:\Sources\MATLAB\work\dpatraces\trace.mat','Writable',true);

for trace_index = 0:trace_num-1
    disp(['Converting Trace ',num2str(trace_index,'%05d'),' ...']);
    trace_text_name = ['F:\Sources\MATLAB\work\dpatraces\tracetexts\tracetext',num2str(trace_index,'%05d')];
    trace_current = importdata(trace_text_name)';
    trace_file.trace(trace_index+1,1) = {trace_current};
end

fprintf('\n%s\n\n','********************* Mission Succeeded *********************');
whos('-file','F:\Sources\MATLAB\work\dpatraces\trace.mat');
toc;