%% myattack
function myattack()
tic
% InterByteMatrixTest()
% HWByteMatrixTest()
% size(CorrelationMatrix(5,1))
% PlotCorrelation(50,1)
% BinToHexTest()
% HexToBinTest
% ShiftTest()
% trace_mat = LoadTrace(20);
% [leak_points_offset,leak_points_sbox_i,leak_points_sbox_o] = Leakage(200,100);
% [leak_trace_offset,leak_trace_sbox_i,leak_trace_sbox_o] = LeakTrace(10000);
% TemplateBuild(10000);
% offset_guess = TemplateMatch(100);
toc
end

%% KeyGuess
function key_guess = KeyGuess(trace_num)
% trace_num: Number of traces used to guess keys
% A good method is using traces from 1 to trace_num and observe the changes of correct rate of key guessing

% Step 1 - Template Attack Offsets
offset_guess = TemplateMatch(10000);

% Step 2 - Load Sbox Leak Traces, Plaintexts and Correct Key
load('leak_trace.mat','leak_trace_sbox_i','leak_trace_sbox_o');
[plain_text,~] = MyInputs(trace_num);
cipher_key = upper('6cecc67f287d083deb8766f0738b36cf164ed9b246951090869d08285d2e193b');
key_correct = cell(1,16);
for i = 1:16
    key_correct{i} = [cipher_key(2*i-1),cipher_key(2*i)];
end

% Step 3 - Compute Inter Values and Corresponding Hamming Weight
for byte_num = 1:16
    inter_mat_sbox_o = cell(trace_num,256);
    for key_num = 0:255
        key_byte = dec2hex(key_num,2);
        for i = 1:trace_num
            [~,~,~,inter_mat_sbox_o{i,key_num+1}] = InterByte(key_byte, plain_text{i},offset{i},byte_num);
        end
    end
end
% Step 4 - Compute Correlation Matrix and Select Most Possible Key

% Step 5 - Compute Correct Rate of Key Guessing


end



%% TemplateMatch
function offset_guess = TemplateMatch(trace_num)
% trace_num : Number of traces, we guess their offsets and provide them for later key guessing
% offset_guess: [ trace_num x 1 ] double

% Step 1 - Load Traces, Templates and Offsets
disp('[*] Loading OFFSET Leak Traces, Templates and Correct OFFSETs ...');
load('leak_points.mat','leak_points_offset');  % [    1 x N  ]      - Here N = 100
load('offset_template.mat');                   % [ 10000 x N ] cell - '10000' is the number used to build template
load('leak_trace.mat','leak_trace_offset');    % [ 10000 x N ] 
[~,offset] = MyInputs(trace_num); % offset: [trace_num x 1] cell
offset = cell2mat(offset);
offset_guess = zeros(trace_num,1);
offset_template = cell2mat(offset_template);
% Step 2 - Compare Real Trace with Templates and Select the Most Possible Offset
disp('[*] Comparing Real Trace with Templates and Selecting the Most Possible Offset ...');
N = size(leak_points_offset,2);
for i = 1:trace_num
    diff = bsxfun(@minus,offset_template,leak_trace_offset(i,:)); % [ 16 x N ]
    sum_of_squares = sum(diff.^2,2);                              % [ 16 x 1 ]
    [~,min_index] = min(sum_of_squares);
    offset_guess(i,1) = min_index - 1; % Offset begins from 0, while matlab begins from 1.
end
% Step 3 - Compute Correct Rate of Offset Guessing
disp('[*] Computing Correct Rate of Offset Guessing ...');
num_total    = trace_num;
comparison   = (offset(1:num_total,1) == offset_guess);
num_correct  = sum(comparison); % Or you can use nnz() here, but nnz() is much slower.
correct_rate = num_correct / num_total

end
%% TemplateBuild
function offset_template = TemplateBuild(trace_num)
% trace_num : Number of traces to build templates
disp('[*] Building Templates of OFFSET ...');
% Step 1 - Load Trace and Select Leak Points
disp(['    ','[*] Loading Trace and Selecting Leak Points', ' ...']);
mf = matfile('F:\Sources\MATLAB\work\dpatraces\tracemat.mat');
load('leak_points.mat','leak_points_offset');
load('leak_trace.mat','leak_trace_offset');

[~,offset] = MyInputs(trace_num); % offset: [trace_num x 1] cell
offset = cell2mat(offset);

% Step 2 - Classify Traces to 16 Groups by Offset Values
disp(['    ','[*] Classifying Traces to 16 Groups', ' ...']);
offset_group = cell(16,1);
offset_trace = cell(16,1);
offset_template = cell(16,1);
for offs =1:16
    offset_group{offs} = find(offset==(offs-1))';
end
for offs = 1:16
    offset_trace{offs} = leak_trace_offset(offset_group{offs},:);
end
% Step 3 - Build Templates with different offs
disp(['    ','[*] Build Templates with different offs', ' ...']);
% Here the template is the mean value of each column
for offs = 1:16
    offset_template{offs} = mean(offset_trace{offs},1); % Mean of each column
end
offset_template_file = 'offset_template.mat';
save(offset_template_file,'offset_template','-v7.3');

disp('[+] Templates of OFFSET Built !');
end

%% LeakTrace
% Only save the leak points of each trace
function [leak_trace_offset,leak_trace_sbox_i,leak_trace_sbox_o] = LeakTrace(trace_num)
% trace_num : Number of traces, for each trace we only save the leak points
% N: Number of Leakage Points -  About 50 to 100
% leak_trace_offset: [ trace_num x N ]
% leak_trace_sbox_i: [ trace_num x N x 16]
% leak_trace_sbox_o: [ trace_num x N x 16]

% Step 1 - Load Traces and Leak Points
disp('[*] Loading Traces and Leak Points ...');
mf = matfile('F:\Sources\MATLAB\work\dpatraces\tracemat.mat');
load('leak_points.mat');
N = size(leak_points_offset,2);            % Here N is same (100) for offset and sbox_io
leak_trace_offset = zeros(trace_num,N);
leak_trace_sbox_i = zeros(trace_num,N,16); % The 3rd dimension is byte_num, here is 16
leak_trace_sbox_o = zeros(trace_num,N,16);

% Step 2 - Save the leak points on each trace for offsets and sbox
disp('[*] Saving the leak points on each trace for offsets and sbox ...');
% leak_trace = mf.tracemat(1:trace_num,leak_points_offset);
% Why I do not use the code on the line above?
% Because ranges for MatFile objects must increase in equally spaced intervals.

disp(['    ','[*] Processing OFFSET Leak Traces', ' ...']);
j = 1; 
% Variable 'j' is used to guarantee the leak_trace index from 1 to N
for col = leak_points_offset
    disp(['    ','    ** Processing Column ', num2str(j,'%03d'),' ...']);
    leak_trace_offset(:,j) = mf.tracemat(1:trace_num,col);
    j = j + 1;
end

disp(['    ','[*] Processing SBOX_I Leak Traces', ' ...']);
for byte_num = 1:16
    disp(['    ','    ** Processing Sbox_i Byte ', num2str(byte_num,'%02d'),' ...']);
    j = 1;
    for col = leak_points_sbox_i(byte_num,:)
        disp(['    ','       *** Processing Sbox_i Column ', num2str(j,'%03d'),' ...']);
        leak_trace_sbox_i(:,j,byte_num) = mf.tracemat(1:trace_num,col);
        j = j + 1;
    end
end

disp(['    ','[*] Processing SBOX_O Leak Traces', ' ...']);
for byte_num = 1:16
    disp(['    ','    ** Processing Sbox_o Byte ', num2str(byte_num,'%02d'),' ...']);
    j = 1;
    for col = leak_points_sbox_o(byte_num,:)
        disp(['    ','       *** Processing Sbox_o Column ', num2str(j,'%03d'),' ...']);
        leak_trace_sbox_o(:,j,byte_num) = mf.tracemat(1:trace_num,col);
        j = j + 1;
    end
end

leak_trace_file = 'leak_trace.mat';
save(leak_trace_file,'leak_trace_offset','leak_trace_sbox_i','leak_trace_sbox_o','-v7.3');
disp('[+] Leak traces saved !');
whos('-file','leak_trace.mat');

end

%% Leakage
% Discover leak points of offset and sbox_io
function [leak_points_offset,leak_points_sbox_i,leak_points_sbox_o] = Leakage(trace_num,N)
% trace_num : Number of traces to distinguish leak points
% N: Number of Leakage Points -  About 50 to 100
% leak_points_offset  : [ 1 x N]
% leak_points_sbox_in : [16 x N]
% leak_points_sbox_out: [16 x N]
% Element of the leak matrix is the position of intereting points
% byte_num: The postion of each byte  1-16
% sbox_i: Inter value of sbox input (Masked)
% sbox_o: Inter value of sbox output(Masked)

% ******** Variables Preallocation ******** %
cipher_key          = upper('6cecc67f287d083deb8766f0738b36cf164ed9b246951090869d08285d2e193b');
[plain_text,offset] = MyInputs(trace_num);
disp('[*] Loading trace file ...');
mf = matfile('F:\Sources\MATLAB\work\dpatraces\tracemat.mat');
disp('[+] Trace file loaded !');

% ******** Offset Leakage ******** %
disp('[*] Discovering OFFSET leak points ...');
% Step 1 - Compute Inter Values and Hamming Weight
disp(['    ','[*] Computing Inter Values and Hamming Weight', ' ...']);
offs = cell(trace_num,1);
for i = 1:trace_num
    offs{i} = dec2hex(offset{i},2);
end
hw_offs = HWMat(offs);
% Step 2 - Compute Correlation Matrix and Plot
disp(['    ','[*] Computing Correlation Matrix and Plotting', ' ...']);
corr_offs = corr(hw_offs,mf.tracemat(1:trace_num,:)); % [1 x T]
% figure;
% plot(corr_mat_offs);
% Step 3 - Sort Correlation Matrix and Get Leak Points
disp(['    ','[*] Sorting Correlation Matrix and Getting Leak Points', ' ...']);
[corr_offs_sorted,corr_offs_order] = sort(corr_offs,2,'descend');
% leak_value_offset = corr_offs_sorted(:,1:N); % [16 x N]
leak_points_offset = corr_offs_order(:,1:N); % [1 x N]
disp('[+] OFFSET leak points discovered !');

% ******** Sbox Leakage ******** %
disp('[*] Discovering SBOX leak points ...');
% Step 1 - Compute Inter Values and Hamming Weight
disp(['    ','[*] Computing Inter Values and Hamming Weight', ' ...']);
sbox_i              = cell(trace_num,16);
sbox_o              = cell(trace_num,16);
for byte_num = 1:16
    key_byte = cipher_key(byte_num*2-1:byte_num*2);
    for i = 1:trace_num
        [~,~,sbox_i{i,byte_num},sbox_o{i,byte_num}] = InterByte(key_byte, plain_text{i},offset{i},byte_num);
    end
%     disp(['    ','[*] Processing Byte ', num2str(byte_num,'%02d'), ' ...']);
end
hw_sbox_i = HWMat(sbox_i);
hw_sbox_o = HWMat(sbox_o);
% Step 2 - Compute Correlation Matrix and Plot
disp(['    ','[*] Computing Correlation Matrix and Plotting', ' ...']);
corr_sbox_i = corr(hw_sbox_i,mf.tracemat(1:trace_num,:)); % [16 x T]
corr_sbox_o = corr(hw_sbox_o,mf.tracemat(1:trace_num,:)); % [16 x T]
% figure;
% for j = 1:16
%     p(j) = plot(corr_sbox_i(j,:),'DisplayName',['Byte ',num2str(j,'%02d'),' - ','Key ',cipher_key(j*2-1:j*2)]);
%     hold on;
% end
% plotbrowser('on');
% Step 3 - Sort Correlation Matrix and Get Leak Points
disp(['    ','[*] Sorting Correlation Matrix and Getting Leak Points', ' ...']);
[corr_sbox_i_sorted,corr_sbox_i_order] = sort(corr_sbox_i,2,'descend');
[corr_sbox_o_sorted,corr_sbox_o_order] = sort(corr_sbox_o,2,'descend');
% leak_value_sbox_i = corr_sbox_i_sorted(:,1:N); % [16 x N]
% leak_value_sbox_o = corr_sbox_o_sorted(:,1:N); % [16 x N]
leak_points_sbox_i = corr_sbox_i_order(:,1:N); % [16 x N]
leak_points_sbox_o = corr_sbox_o_order(:,1:N); % [16 x N]
disp('[+] SBOX leak points discovered !');

disp('[*] Saving leak points file ...');
leak_points_file = 'leak_points.mat';
save(leak_points_file,'leak_points_offset','leak_points_sbox_i','leak_points_sbox_o','-v7.3');
whos('-file',leak_points_file);
disp('[+] Leak points file saved !');
% load('leak_points.mat');

end

%% PlotCorrelation
function PlotCorrelation(trace_num,byte_num)
corr_mat = CorrelationMatrix(trace_num,byte_num);
% for i = 1:256
%     if mod(i,16) == 1
%         figure;
%     end
%     plot(corr_mat(i,:))
%     hold on;
% end
end
%% CorrelationMatrix
function corr_mat = CorrelationMatrix(trace_num,byte_num)
hw_byte_mat = HWByteMatrix(trace_num,byte_num);  % D x K
trace_mat   = LoadTrace(trace_num);              % D x T
corr_mat    = corr(hw_byte_mat,trace_mat);       % K x T
end

%% HWByteMatrix
function hw_byte_mat = HWByteMatrix(trace_num,byte_num)
inter_byte_mat = InterByteMatrix(trace_num,byte_num);
hw_byte_mat = zeros(trace_num,256);
for row = 1:trace_num
    for col = 1:256
        hw_byte_mat(row,col) = HWByte(inter_byte_mat{row,col});
    end
end
end

%% HWMat
% Input:  Bytes Characters Matrix - Hex cell   string
% Output: Hamming Weight   Matrix - Dec double number
function HWMat = HWMat(v_mat)
[row,col] = size(v_mat);
HWMat = zeros(row,col);
for i = 1:row
    for j = 1:col
        HWMat(i,j) = HWByte(v_mat{i,j});
    end
end
end

%% HWByte
% Compute the Hamming Weight of a given byte
function HW = HWByte(byte)
bin_vec = HexToBin(byte);
HW = nnz(bin_vec);
end

%% InterByteMatrix
function inter_byte_mat = InterByteMatrix(trace_num,byte_num)
% byte_num: The position of each byte: 0-15
[plain_text,offset] = MyInputs(trace_num);

inter_byte_mat = cell(trace_num,256);

% Guess one byte of key through all 256 possibilities
for key_num = 0:255
    key_byte = dec2hex(key_num,2);
    for i = 1:trace_num
        [~,~,~,inter_byte_mat{i,key_num+1}] = ...
            InterByte(key_byte, plain_text{i},offset{i},byte_num);
    end
end
end

%% InterByte
% Compute Inter Values of one specified byte of a state in AES
% v3: sbox_i
% v4: sbox_o
function [v1,v2,v3,v4] = InterByte(key_byte,plain_text,offset,byte_num)
v1 = plain_text{byte_num};
v2 = ByteXor(v1,MaskByte(offset,byte_num));
v3 = ByteXor(v2,key_byte);

v_tmp = ByteXor(v3,MaskByte(offset,byte_num));
v_tmp = SubBytesByte(v_tmp);
v4 = ByteXor(v_tmp,MaskByte(offset+1,byte_num));
end

%% MyInputs
% Output cell matrix consisting of given plain_text and offsets
% plain_text: [ trace_num x 1 ] cell 
%     - In each cell is a [ 4 x 4 ] cell

function [plain_text,offset] = MyInputs(trace_num)
indexfile = fopen('../dpav4_rsm_index');
index = textscan(indexfile,'%s %s %s %s %s %s',trace_num); 
fclose(indexfile);

% Size of index: [trace_num x 1 cell] x 6
% Column    1       2          3         4         5          6 
%          Key  Plaintext  Ciphertext  Offset  Directory  TraceFile
% 
% Example:
% index{2}:   = Plaintext    : [ trace_num x  1 ] cell
% index{2}{1}:= Plaintext{1} :         [ 1 x 32 ] string  - '448ff4f8eae2cea393553e15fd00eca1'
% TextToMatrix(plain_text{i}); =>      [ 4 x  4 ] cell    - Each element is one byte (2 characters)

plain_text  = index{2};
offset      = index{4};

for i = 1:trace_num
    plain_text{i}  = TextToMatrix(plain_text{i});
    offset{i}      = HexToDec(offset{i});
end
end

%% CircShiftLeft
% CircShiftLeft is 2x faster than circshift
function vec_out = CircShiftLeft(vec_in,shift_bits)
if class(vec_in) == 'cell'
    vec_out = {vec_in{shift_bits+1:end} vec_in{1:shift_bits}};
else
    vec_out = [vec_in(shift_bits+1:end) vec_in(1:shift_bits)];
end
end
%% ShiftLeft
% After using ShifLeft instead of bitsll(),
% the whole AES is 3 times faster than the original one.
function vec_out = ShiftLeft(vec_in,shift_bits,filled_value)
filler_array = filled_value*ones(1,shift_bits);
vec_out = [vec_in(shift_bits+1:end) filler_array];
end

%% HexToDec
% HexToDec is 8x faster than hex2dec
function dec_num = HexToDec(hex_str)
hex_str = upper(hex_str);
switch hex_str
    case '0'  
        dec_num = 0;
    case '1'
        dec_num = 1;
    case '2'
        dec_num = 2;
    case '3'
        dec_num = 3;
    case '4'
        dec_num = 4;
    case '5'
        dec_num = 5;
    case '6'
        dec_num = 6;
    case '7'
        dec_num = 7;
    case '8'
        dec_num = 8;
    case '9'
        dec_num = 9;
    case 'A'
        dec_num = 10;
    case 'B'
        dec_num = 11;
    case 'C'
        dec_num = 12;
    case 'D'
        dec_num = 13;
    case 'E'
        dec_num = 14;
    case 'F'
        dec_num = 15;
    otherwise
        dec_num = 0;
    end
end

%% HexToBin
% HexToBin uses Switch-Case, is 3x faster than HexToBinOld
% On average, Switch-Case is slightly faster than If-Else, about 5% in test
function bin_vec = HexToBin(hex_str)
hex_str = upper(hex_str);
hex_str_num = numel(hex_str);
bin_vec = zeros(1,4*hex_str_num);
for i = 1:hex_str_num
    switch hex_str(i)
        case '0'  
            bin_vec(1,4*i-3:4*i) = [0 0 0 0];
        case '1'
            bin_vec(1,4*i-3:4*i) = [0 0 0 1];
        case '2'
            bin_vec(1,4*i-3:4*i) = [0 0 1 0];
        case '3'
            bin_vec(1,4*i-3:4*i) = [0 0 1 1];
        case '4'
            bin_vec(1,4*i-3:4*i) = [0 1 0 0];
        case '5'
            bin_vec(1,4*i-3:4*i) = [0 1 0 1];
        case '6'
            bin_vec(1,4*i-3:4*i) = [0 1 1 0];
        case '7'
            bin_vec(1,4*i-3:4*i) = [0 1 1 1];
        case '8'
            bin_vec(1,4*i-3:4*i) = [1 0 0 0];
        case '9'
            bin_vec(1,4*i-3:4*i) = [1 0 0 1];
        case 'A'
            bin_vec(1,4*i-3:4*i) = [1 0 1 0];
        case 'B'
            bin_vec(1,4*i-3:4*i) = [1 0 1 1];
        case 'C'
            bin_vec(1,4*i-3:4*i) = [1 1 0 0];
        case 'D'
            bin_vec(1,4*i-3:4*i) = [1 1 0 1];
        case 'E'
            bin_vec(1,4*i-3:4*i) = [1 1 1 0];
        case 'F'
            bin_vec(1,4*i-3:4*i) = [1 1 1 1];
        otherwise
            bin_vec(1,4*i-3:4*i) = [0 0 0 0];
    end
end
end
%% HexToBinOld
% This function is 10 times faster than hexToBinaryVector
% One strange phenomenon: 
%   The first call of HexToBin is sometimes lower than hexToBinaryVector
% After using HexToBin, the whole AES is 2 times faster than the original one.
function bin_vec = HexToBinOld(hex_str)
global hex_table;
global bin_table;
hex_str = upper(hex_str);
hex_str_num = numel(hex_str);
bin_vec = zeros(1,4*hex_str_num);

for i = 1:hex_str_num
    bin_vec(1,4*i-3:4*i) = bin_table(hex_table == hex_str(i), :);
end
end

%% BinToHex
% BinToHex uses a binary tree, though ugly, is 20x faster than BinToHexOld
function hex_str = BinToHex(bin_vec)
hex_str_num = numel(bin_vec)/4;
% hex_str = blanks(hex_str_num);
for i = 1:hex_str_num
    if bin_vec(4*i-3) == 0
        if bin_vec(4*i-2) == 0
            if bin_vec(4*i-1) == 0
                if (bin_vec(4*i) == 0)  hex_str(i) = '0';
                else                    hex_str(i) = '1';
                end
            else
                if (bin_vec(4*i) == 0)  hex_str(i) = '2';
                else                    hex_str(i) = '3';
                end
            end
        else
            if bin_vec(4*i-1) == 0
                if (bin_vec(4*i) == 0)  hex_str(i) = '4';
                else                    hex_str(i) = '5';
                end
            else
                if (bin_vec(4*i) == 0)  hex_str(i) = '6';
                else                    hex_str(i) = '7';
                end
            end
        end
    else
        if bin_vec(4*i-2) == 0
            if bin_vec(4*i-1) == 0
                if (bin_vec(4*i) == 0)  hex_str(i) = '8';
                else                    hex_str(i) = '9';
                end
            else
                if (bin_vec(4*i) == 0)  hex_str(i) = 'A';
                else                    hex_str(i) = 'B';
                end
            end
        else
            if bin_vec(4*i-1) == 0
                if (bin_vec(4*i) == 0)  hex_str(i) = 'C';
                else                    hex_str(i) = 'D';
                end
            else
                if (bin_vec(4*i) == 0)  hex_str(i) = 'E';
                else                    hex_str(i) = 'F';
                end
            end
        end                    
    end
end
end
%% BinToHexOld
% After using BinToHexOld, the whole AES is 3 times faster than binaryVectorToHex.
function hex_str = BinToHexOld(bin_vec)
hex_table = [ 
    '0','1','2','3','4','5','6','7', ...
    '8','9','A','B','C','D','E','F'
    ]; 
bin_table = [
    0 0 0 0; 0 0 0 1; 0 0 1 0; 0 0 1 1;
    0 1 0 0; 0 1 0 1; 0 1 1 0; 0 1 1 1;
    1 0 0 0; 1 0 0 1; 1 0 1 0; 1 0 1 1;
    1 1 0 0; 1 1 0 1; 1 1 1 0; 1 1 1 1;
    ];
hex_str_num = numel(bin_vec)/4;
hex_str = blanks(hex_str_num);

for i = 1:hex_str_num
    [IsMember,Index] = ismember(bin_vec(1,4*i-3:4*i),bin_table,'rows');
    hex_str(i) = hex_table(Index);
end
end

%% TextToMatrix
% Only applicable for limited conditions.
% Output [ 4 x N ] cell
function matrix = TextToMatrix(text)
% matrix: [ 4 x N ] cell
% Each element of the matrix is a byte (2 characters).
row = 4;
col = numel(text)/8;
matrix = cell(row,col);
for i = 1:row*col
    matrix{i} = [text(2*i-1),text(2*i)];
end
end
%% MatrixToText
function text = MatrixToText(matrix)
% Size of matrix: 4 by N
text = blanks(2*numel(matrix));
for i = 1:numel(matrix)
    text(2*i-1) = matrix{i}(1);
    text(2*i)   = matrix{i}(2);
end
end

%% ByteXor
function byte_out = ByteXor(byte1,byte2)
binvec1     = HexToBin(byte1);
binvec2     = HexToBin(byte2);
binvec_xor  = bitxor(binvec1,binvec2);
byte_out    = BinToHex(binvec_xor);
end

%% MatrixXor
function matrix_out = MatrixXor(matrix1,matrix2)
% Type of matrix 1 & 2 :    Cell
% Element of matrix 1 & 2 : Byte
matrix_out = cell(size(matrix1));
for i = 1:numel(matrix1)
    matrix_out{i} = ByteXor(matrix1{i},matrix2{i});
end
end

%% SubBytesByte
function byte_out = SubBytesByte(byte_in)
sbox = { 
    '63','7C','77','7B','F2','6B','6F','C5','30','01','67','2B','FE','D7','AB','76';
    'CA','82','C9','7D','FA','59','47','F0','AD','D4','A2','AF','9C','A4','72','C0';
    'B7','FD','93','26','36','3F','F7','CC','34','A5','E5','F1','71','D8','31','15';
    '04','C7','23','C3','18','96','05','9A','07','12','80','E2','EB','27','B2','75';
    '09','83','2C','1A','1B','6E','5A','A0','52','3B','D6','B3','29','E3','2F','84';
    '53','D1','00','ED','20','FC','B1','5B','6A','CB','BE','39','4A','4C','58','CF';
    'D0','EF','AA','FB','43','4D','33','85','45','F9','02','7F','50','3C','9F','A8';
    '51','A3','40','8F','92','9D','38','F5','BC','B6','DA','21','10','FF','F3','D2';
    'CD','0C','13','EC','5F','97','44','17','C4','A7','7E','3D','64','5D','19','73';
    '60','81','4F','DC','22','2A','90','88','46','EE','B8','14','DE','5E','0B','DB';
    'E0','32','3A','0A','49','06','24','5C','C2','D3','AC','62','91','95','E4','79';
    'E7','C8','37','6D','8D','D5','4E','A9','6C','56','F4','EA','65','7A','AE','08';
    'BA','78','25','2E','1C','A6','B4','C6','E8','DD','74','1F','4B','BD','8B','8A';
    '70','3E','B5','66','48','03','F6','0E','61','35','57','B9','86','C1','1D','9E';
    'E1','F8','98','11','69','D9','8E','94','9B','1E','87','E9','CE','55','28','DF';
    '8C','A1','89','0D','BF','E6','42','68','41','99','2D','0F','B0','54','BB','16'
    };
row = HexToDec(byte_in(1))+1;
col = HexToDec(byte_in(2))+1;
byte_out = sbox{row,col};
end

%% MaskByte
function mask_byte = MaskByte(offset,byte_num)
%global maskbox;
maskbox = {
    '00','0F','36','39','53','5C','65','6A', ...
    '95','9A','A3','AC','C6','C9','F0','FF'
    };
% mask = circshift(maskbox,-offset,2);
% mask = CircShiftLeft(maskbox,offset);
% mask_byte = mask{byte_num};
mask_byte = maskbox{mod(byte_num+offset-1,16)+1};
end

%% LoadTrace
% These two functions are not used anymore: LoadTrace & SaveTrace
% Update to 'trace_processing.m'
function trace_mat = LoadTrace(trace_num)
% trace_all = load('trace_all.mat','trace_all');
mydata = matfile('trace_all.mat');
trace_mat = mydata.trace_all(1:trace_num,:);
% save trace_mat trace_mat
end
%% SaveTrace
function trace_all = SaveTrace(trace_num)
filename = cell(1,trace_num);
trace = cell(1,trace_num);
for i = 1:trace_num
    if i <= 10
        filename{i} = strcat('../traces/mytracetexts/tracetexts0000',int2str(i-1));
    elseif i >= 11 && i <= 100
        filename{i} = strcat('../traces/mytracetexts/tracetexts000',int2str(i-1));
    elseif i >= 101 && i <= 1000
        filename{i} = strcat('../traces/mytracetexts/tracetexts00',int2str(i-1));
    elseif i >= 1001 && i <= 10000
        filename{i} = strcat('../traces/mytracetexts/tracetexts0',int2str(i-1));
    end
    trace{i} = importdata(filename{i})';  % Each trace: [1 x 435002]
end
trace = reshape(trace,trace_num,1);       % Cell:  [1 x 435002 double] x trace_num
trace_all = cell2mat(trace);              % Array: [trace_num x 435002 double]
save('trace_all.mat','trace_all','-v7.3');
end
%% BinToHexTest
function BinToHexTest()
InitiateConstants();
vec1 = [0 1 1 0 1 1 1 1];
vec2 = [1 0 0 1 1 0 0 0];
tic
for i = 1:10000
    t1 = BinToHexOld(vec1);
    t2 = BinToHexOld(vec2);
end
toc
tic
for i = 1:10000
    t3 = BinToHex(vec1);
    t4 = BinToHex(vec2);
end
toc
end
%% HexToBinTest
function HexToBinTest()
hex1 = '37';
hex2 = 'bf';
disp('Old...')
tic
for i = 1:50000
    bin1 = HexToBinOld(hex1);
    bin2 = HexToBinOld(hex2);
end
toc
disp('If Else...')
% tic
% for j = 1:50000
%     bin3 = HexToBinIf(hex1);
%     bin4 = HexToBinIf(hex2);
% end
% toc
disp('Switch Case...')
tic
for j = 1:50000
    bin5 = HexToBin(hex1);
    bin6 = HexToBin(hex2);
end
toc
% isequal(bin1,bin3);
% isequal(bin2,bin4);
isequal(bin1,bin5);
isequal(bin2,bin6);
end
%% InterByteMatrixTest
function InterByteMatrixTest()
inter_byte_mat = InterByteMatrix(4,5)
end
%% HWByteMatrixTest
function HWByteMatrixTest()
hw_byte_mat = HWByteMatrix(5,5)
end
%% ShiftTest
function ShiftTest()
maskbox = {
    '00','0F','36','39','53','5C','65','6A', ...
    '95','9A','A3','AC','C6','C9','F0','FF'
    };
disp('circshift...')
tic
for i = 1:10000
    mask1 = circshift(maskbox,-8,2);
end
toc
disp('CircShiftLeft...')
tic
for i = 1:10000
    mask2 = CircShiftLeft(maskbox,8);
end
toc
isequal(mask1,mask2)
end
