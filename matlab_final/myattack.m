%% myattack
function myattack()

% InterByteMatrixTest()
% HWByteMatrixTest()
% size(CorrelationMatrix(5,1))
% PlotCorrelation(50,1)
% BinToHexTest()
% HexToBinTest
ShiftTest()
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
trace_mat   = RealTrace(trace_num);              % D x T
corr_mat    = corr(hw_byte_mat,trace_mat);       % K x T
end

%% RealTrace
function trace_mat = RealTrace(trace_num)
filename = cell(1,trace_num);
trace = cell(1,trace_num);   
for i = 1:trace_num
    if i <= 10
        filename{i} = strcat('../traces/mytracetexts/tracetexts0000',int2str(i-1));
    elseif i >= 11 && i <= 100
        filename{i} = strcat('../traces/mytracetexts/tracetexts000',int2str(i-1));
    elseif i >= 101 && i <= 1000
        filename{i} = strcat('../traces/mytracetexts/tracetexts00',int2str(i-1));
    end
    trace{i} = importdata(filename{i})';  % Each trace: [1 x 435002]
end
trace = reshape(trace,trace_num,1);       % Cell:  [1 x 435002 double] x trace_num
trace_mat = cell2mat(trace);              % Array: [trace_num x 435002 double]
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

%% HWByte
function HW = HWByte(byte)
bin_vec = HexToBin(byte);
HW = nnz(bin_vec);
end


%% InterByteMatrix
function inter_byte_mat = InterByteMatrix(trace_num,byte_num)
% byte_num: The position of each byte
[plain_text,offset] = MyInputs(trace_num);

inter_byte_mat = cell(trace_num,256);  

% Guess one byte of key through all 256 possibilities
for key_num = 0:255
    key_byte = dec2hex(key_num,2);
    for i = 1:trace_num
        inter_byte_mat{i,key_num+1} = ...
            InterByte(key_byte, plain_text{i},offset{i},byte_num);
    end
end
end

%% InterByte
function inter_byte = InterByte(key_byte,plain_text,offset,byte_num)
InitiateConstants();
byte_tmp = plain_text{byte_num};
byte_tmp = ByteXor(byte_tmp,MaskByte(offset,byte_num));
byte_tmp = ByteXor(byte_tmp,key_byte);

byte_tmp = ByteXor(byte_tmp,MaskByte(offset,byte_num));
byte_tmp = SubBytesByte(byte_tmp);
byte_tmp = ByteXor(byte_tmp,MaskByte(offset+1,byte_num));
inter_byte = byte_tmp;
end


%% MyInputs
function [plain_text,offset] = MyInputs(trace_num)

indexfile = fopen('../dpav4_rsm_index');
index = textscan(indexfile,'%s %s %s %s %s %s',trace_num); 
fclose(indexfile);

% Size of index: [trace_num x 1 cell] x 6
% Column    1       2          3         4         5          6 
%          Key  Plaintext  Ciphertext  Offset  Directory  TraceFile
% 
% Example:
% index{2}:     Plaintext   ALL: [trace_num x 1]
% index{2}{1}:  Plaintext 00000: 448ff4f8eae2cea393553e15fd00eca1

plain_text  = index{2};
offset      = index{4};

for i = 1:trace_num
    plain_text{i}  = TextToMatrix(plain_text{i});
    offset{i}      = hex2dec(offset{i});
end
end

%% InitiateConstants
function InitiateConstants()
global sbox;
global RC;
global mixbox;
global maskbox;

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

RC = { % Round Constants
    '01','02','04','08','10','20','40';
    '00','00','00','00','00','00','00';
    '00','00','00','00','00','00','00';
    '00','00','00','00','00','00','00'
    };
mixbox = {
    2,3,1,1;
    1,2,3,1;
    1,1,2,3;
    3,1,1,2
    };
maskbox = {
    '00','0F','36','39','53','5C','65','6A', ...
    '95','9A','A3','AC','C6','C9','F0','FF'
    };
global hex_table;
global bin_table;
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
hex_str = blanks(hex_str_num);
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
global hex_table;
global bin_table;
hex_str_num = numel(bin_vec)/4;
hex_str = blanks(hex_str_num);

for i = 1:hex_str_num
    [IsMember,Index] = ismember(bin_vec(1,4*i-3:4*i),bin_table,'rows');
    hex_str(i) = hex_table(Index);
end
end

%% TextToMatrix
function matrix = TextToMatrix(text)
% Size of matrix: 4 by N
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
global sbox;
row = hex2dec(byte_in(1))+1;
col = hex2dec(byte_in(2))+1;
byte_out = sbox{row,col};
end

%% MaskByte
function mask_byte = MaskByte(offset,byte_num)
global maskbox;
% mask = circshift(maskbox,-offset,2);
mask = CircShiftLeft(maskbox,offset);
% mask = reshape(mask,4,4);
mask_byte = mask{byte_num};
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
global maskbox;
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
