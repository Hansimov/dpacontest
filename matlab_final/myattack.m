%% myattack
function myattack()
trace_num = 11;
[key,plain_text,cipher_text,offset,trace] = Inputs(trace_num)

vin1 = cell(1,trace_num);
% 
% for i = 1:1
% [vin1,vin2,vout1,vout2] = GetInterValue(key{i},plain_text{i},cipher_text{i},offset{i})
% end

end

%% Inputs
function [key,plain_text,cipher_text,offset,trace] = Inputs(trace_num)
key = '6cecc67f287d083deb8766f0738b36cf164ed9b246951090869d08285d2e193b';
key = TextToMatrix(key);

% indexfilename = '../dpav4_rsm_index';
indexfile = fopen('../dpav4_rsm_index');
index = textscan(indexfile,'%s %s %s %s %s %s',trace_num); 
fclose(indexfile);

% Size of index: [trace_num x 1 cell] x 6
% Column    1       2          3         4         5          6 
%          Key  Plaintext  Ciphertext  Offset  Directory  TraceFile
% 
% Example:
% index{2}:     Plaintext   ALL: [100000 x 1]
% index{2}{1}:  Plaintext 00000: 448ff4f8eae2cea393553e15fd00eca1

plain_text  = index{2};
cipher_text = index{3};
offset      = index{4};

for i = 1:trace_num
    plain_text{i} = TextToMatrix(plain_text{i});
    cipher_text{i} = TextToMatrix(cipher_text{i});
end

offset = hex2dec(offset);

filename = cell(1,trace_num);
trace = cell(1,trace_num);
for i = 1:trace_num
    if i <= 10
        filename{i} = strcat('../traces/mytracetexts/tracetexts0000',int2str(i-1));
    else 
        filename{i} = strcat('../traces/mytracetexts/tracetexts000',int2str(i-1));
    end
    trace{i} = importdata(filename{i})';
end

end

%% GetInterValue
function [vin1,vin2,vout1,vout2] = GetInterValue(key,plain_text,cipher_text,offset)
state = plain_text;
state = MatrixXor(state,Mask(offset));
state = AddRoundKey(state,key(:,1:4));
vin1 = state;
% Only use first round
% state = MaskedSubBytes(state,offset+round-1);
state = MatrixXor(state,Mask(offset));
vin2 = state;
state = SubBytes(state);
vout1 = state;
state = MatrixXor(state,Mask(offset+1)); 
vout2 = state;

state = ShiftRows(state);
state = MixColumns(state);
state = MatrixXor(state,MaskCompensation(offset+round));

end
%% ByteHW
function ByteHW()

end

%% BytePower
function BytePower()
end

function GetCorrelationMatrix()
end

function GetLeakagePosition()

end

%% TextToMatrix
function matrix = TextToMatrix(text)
% Type of text  : characters
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
%% Mask
function mask = Mask(offset)
maskbox = {
    '00','0F','36','39','53','5C','65','6A', ...
    '95','9A','A3','AC','C6','C9','F0','FF'
    };
mask = circshift(maskbox,-offset,2);
mask = reshape(mask,4,4);
end
%% ByteXor
function byte_out = ByteXor(byte1,byte2)
binvec1     = hexToBinaryVector(byte1,8);
binvec2     = hexToBinaryVector(byte2,8);
binvec_xor  = bitxor(binvec1,binvec2);
byte_out    = binaryVectorToHex(binvec_xor);
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
%% AddRoundKey
function state_out = AddRoundKey(state_in,key_in)
state_out = MatrixXor(state_in,key_in);
end
%% SubBytes
function state_out = SubBytes(state_in)
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

% sbox_dec = reshape(hex2dec(sbox),16,16);
state_out = cell(size(state_in));
for i = 1:numel(state_in)
    row = hex2dec(state_in{i}(1))+1;
    col = hex2dec(state_in{i}(2))+1;
    state_out(i) = sbox(row,col);
end
end
%% MaskedSubBytes
function state_out = MaskedSubBytes(state_in,offset)
state_tmp = MatrixXor(state_in,Mask(offset));
state_tmp = SubBytes(state_tmp);
state_out = MatrixXor(state_tmp,Mask(offset+1)); 
end
%% ShiftRows
function state_out = ShiftRows(state_in)
% Size of state_in : 4 x 4
state_out = cell(size(state_in));
% circshift(V,K,D):
%     V: Vector
%     K: Right shift K positions. We need Left shift -K in AES.
%     D: Dimension shifted. D=2 here.
state_out(1,:) = circshift(state_in(1,:), 0,2);
state_out(2,:) = circshift(state_in(2,:),-1,2);
state_out(3,:) = circshift(state_in(3,:),-2,2);
state_out(4,:) = circshift(state_in(4,:),-3,2);
end
%% GFMul
function byte_out = GFMul(num,byte_in)
% C = bitsll(B, N); ---- Bit Shift Left Logical
% Left shift B by N bits. B must be numeric types.
if num == 1
    byte_out = byte_in;
else
    byte_shifted = dec2hex(bitsll(uint8(hex2dec(byte_in)),1));    
    if hex2dec(byte_in(1)) >= 8     % MSB == 1
        byte_xor = ByteXor(byte_shifted,'1B');
    else                            % MSB == 0
        byte_xor = ByteXor(byte_shifted,'00');
    end
    
    if num == 2
        byte_out = byte_xor;
    else    % num ==3
        byte_out = ByteXor(byte_xor,byte_in);
    end
end
end
%% MixColumns
function state_out = MixColumns(state_in)
% Refer to this : 
%   "How to solve MixColumns":
%      https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
mixbox = {
    2,3,1,1;
    1,2,3,1;
    1,1,2,3;
    3,1,1,2
    };
state_out = cell(size(state_in));

for row = 1:size(state_in,1)
    for col = 1:size(state_in,2)
        mul_tmp = '00';
        xor_tmp = '00';
        for k = 1:4
            mul_tmp = GFMul(mixbox{row,k},state_in{k,col});
            xor_tmp = ByteXor(xor_tmp,mul_tmp);
        end
        state_out{row,col} = xor_tmp;
    end
end
end
%% MaskCompensation
function mask = MaskCompensation(offset)
mask_tmp = Mask(offset);
mask_tmp = ShiftRows(mask_tmp);
mask_tmp = MixColumns(mask_tmp);
mask = MatrixXor(mask_tmp,Mask(offset));
end