% I comment this file, in oder to avoid changing the '.mat' file by mistake.

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