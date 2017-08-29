%% trace_processing
function trace_processing()
% % % Bz2ToTextSingle();
% % % TextToCell();
% % % CellToMat();
end

%% CellToMat
function CellToMat()
% Why I comment this file? To avoid changing the '.mat' file by mistake.

% tic
% cf = matfile('F:\Sources\MATLAB\work\dpatraces\trace.mat');
% mf = matfile('F:\Sources\MATLAB\work\dpatraces\tracemat.mat');
% mf.Properties.Writable = true;
% toc

% whos('-file','F:\Sources\MATLAB\work\dpatraces\tracemat.mat');

% group = 50;
% tic
% for i = 1:200
%     trace_current = cf.trace(group*(i-1)+1:group*i,1);
%     disp(['Converting Traces ',num2str(group*(i-1)+1,'%05d'),' - ',num2str(group*i,'%05d')]);
%     mf.tracemat(group*(i-1)+1:group*i,:) = cell2mat(trace_current);
% end
% toc
end

%% TextToCell
function TextToCell()
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
end

%% Bz2ToTextSingle
function Bz2ToTextSingle()
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
end

%% Bz2ToTextBlock
function Bz2ToTextBlock()
trace_num = 100;
trace = cell(trace_num,1);
program_name = '"F:\Sources\MATLAB\work\dpatraces\traces2text.exe"';
version_name = 'v4_RSM';
parfor trace_index = 0:trace_num-1
    trace_file_name = ['F:\Sources\MATLAB\work\dpatraces\00000\Z1Trace',num2str(trace_index,'%05d'),'.trc.bz2'];
    trace_text_name = ['F:\Sources\MATLAB\work\dpatraces\tracetexts\tracetext',num2str(trace_index,'%05d')];
    echos = ['echo Processing trace ', num2str(trace_index,'%05d'),' ...'];
    cmd_convert = [program_name,' ',version_name,' ',trace_file_name,' ',trace_text_name];
    cmd_delete  = ['del ',trace_text_name];
    system(echos);
    system(cmd_convert);
    trace{trace_index+1} = importdata(trace_text_name)';
    system(cmd_delete);
end
trace_all = cell2mat(trace);              % Array: [trace_num x 435002 double]
% save('F:\Sources\MATLAB\work\dpatraces\trace_all.mat',['trace',num2str(i,'%02d')],'-v7.3');
save('F:\Sources\MATLAB\work\dpatraces\trace_all.mat','trace_all','-v7.3');
end