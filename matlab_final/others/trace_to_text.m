trace_num = 10000;
% trace = cell(trace_num,1);

program_name = '"F:\Sources\MATLAB\work\dpatraces\traces2text.exe"';
version_name = 'v4_RSM';

parfor trace_index = 0:trace_num-1
    trace_file_name = ['F:\Sources\MATLAB\work\dpatraces\00000\Z1Trace',num2str(trace_index,'%05d'),'.trc.bz2'];
    trace_text_name = ['F:\Sources\MATLAB\work\dpatraces\tracetexts\tracetext',num2str(trace_index,'%05d')];
    echos = ['echo Converting trace ', num2str(trace_index,'%05d'),' ...'];
    cmd_convert = [program_name,' ',version_name,' ',trace_file_name,' ',trace_text_name];
%     cmd_delete  = ['del ',trace_text_name];
    system(echos);
    system(cmd_convert);
%     trace{trace_index+1} = importdata(trace_text_name)';
%     system(cmd_delete);
end

% save('F:\Sources\MATLAB\work\dpatraces\trace_all.mat',['trace',num2str(i,'%02d')],'-v7.3');
% save('F:\Sources\MATLAB\work\dpatraces\trace_all.mat','trace_all','-v7.3');

% mytrace = matfile('trace_all.mat');
% trace_mat = mytrace.trace_all(1:trace_num,:);