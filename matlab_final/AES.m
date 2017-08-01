% 256-bit Key:        6cecc67f287d083deb8766f0738b36cf164ed9b246951090869d08285d2e193b 
% 128-bit Plaintext:  448ff4f8eae2cea393553e15fd00eca1
% 128-bit Ciphertext: f71e9995e754e9f711b4027106a72788
% Offset:             8 
% Directory Name:     00000 
% Trace Name:         Z1Trace00000.trc.bz2

%% AES
function AES()
tic
AES_256_Test()
toc
% InitiateConstants();
tic
AES_RSM_Test()
toc
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
%% AES_RSM_Test
function AES_RSM_Test()
cipher_key = '6cecc67f287d083deb8766f0738b36cf164ed9b246951090869d08285d2e193b'
plain_text = '448ff4f8eae2cea393553e15fd00eca1'
% cipher_text = 'f71e9995e754e9f711b4027106a72788'
% plain_text  = 'd0edb7612c4dc8aa42358571649af40c'
% cipher_text = 'f0fbbbb6e7d2befb7b947e9250fcd754'
offset = 8

cipher_text = AES_RSM(cipher_key,plain_text,offset)
% cipher_text = AES_256(cipher_key,plain_text)

end

%% AES_RSM
function cipher_text = AES_RSM(cipher_key,plain_text,offset)
InitiateConstants();
% Refer to these: 
%   "Description of the masked AES of the DPA contest v4": Algorithm 1
%      http://www.dpacontest.org/v4/data/rsm/aes-rsm.pdf

% ---------- AES-256 ---------- %
Nb = 4;                  % Nb: Block Number
Nr = 14;                 % Nr: Round Number
Nk = 8;                  % Nk: Cipher Key Size

cipher_key   = TextToMatrix(cipher_key);
plain_text   = TextToMatrix(plain_text);
expanded_key = KeySchedule(cipher_key);

state = plain_text;

state = MatrixXor(state,Mask(offset));

state = AddRoundKey(state,expanded_key(:,1:Nb));

for round = 1:Nr-1
    state = MaskedSubBytes(state,offset+round-1);
    state = ShiftRows(state);
    state = MixColumns(state);
    state = MatrixXor(state,MaskCompensation(offset+round));
    state = AddRoundKey(state,expanded_key(:,Nb*round+1:Nb*(round+1)));
end

state = MaskedSubBytes(state,offset+Nr-1);
state = ShiftRows(state);
state = AddRoundKey(state,expanded_key(:,Nb*Nr+1:Nb*(Nr+1)));
state = MatrixXor(state,MaskCompensationLastRound(offset+Nr));

cipher_text = state;
cipher_text = MatrixToText(cipher_text);

end

%% AES_256_Test
function AES_256_Test()
plain_text = '448ff4f8eae2cea393553e15fd00eca1'
cipher_key = '6cecc67f287d083deb8766f0738b36cf164ed9b246951090869d08285d2e193b'

cipher_text = AES_256(cipher_key,plain_text)
% cipher_text = 'f71e9995e754e9f711b4027106a72788'
end

%% AES_256
function cipher_text = AES_256(cipher_key,plain_text)
InitiateConstants();
% Refer to these: 
%   "Announcing the ADVANCED ENCRYPTION STANDARD (AES)": Section 5.1 --- Cipher
%      http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

% ---------- AES-256 ---------- %
Nb = 4;                  % Nb: Block Number
Nr = 14;                 % Nr: Round Number
Nk = 8;                  % Nk: Cipher Key Size

cipher_key   = TextToMatrix(cipher_key);
plain_text   = TextToMatrix(plain_text);
expanded_key = KeySchedule(cipher_key);

state = plain_text;

state = AddRoundKey(state,expanded_key(:,1:Nb));

for round = 1:Nr-1
    state = SubBytes(state);
    state = ShiftRows(state);
    state = MixColumns(state);
    state = AddRoundKey(state,expanded_key(:,Nb*round+1:Nb*(round+1)));
end

state = SubBytes(state);
state = ShiftRows(state);
state = AddRoundKey(state,expanded_key(:,Nb*Nr+1:Nb*(Nr+1)));

cipher_text = state;
cipher_text = MatrixToText(cipher_text);
end

%% ShiftLeft
% After using ShifLeft instead of bitsll(),
% the whole AES is 3 times faster than the original one.
function vec_out = ShiftLeft(vec_in,shift_bits,filled_value)
filler_array = filled_value*ones(1,shift_bits);
vec_out = [vec_in(shift_bits+1:end) filler_array];
end

%% HexToBin
% This function is 10 times faster than hexToBinaryVector
% One strange phenomenon: 
%   The first call of HexToBin is sometimes lower than hexToBinaryVector
% After using HexToBin, the whole AES is 2 times faster than the original one.
function bin_vec = HexToBin(hex_str)
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
% After using BinToHex, the whole AES is 3 times faster than the original one.
function hex_str = BinToHex(bin_vec)
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

%% AddRoundKey
function state_out = AddRoundKey(state_in,key_in)
state_out = MatrixXor(state_in,key_in);
end

%% SubBytes
function state_out = SubBytes(state_in)
global sbox;

% sbox_dec = reshape(hex2dec(sbox),16,16);
state_out = cell(size(state_in));
for i = 1:numel(state_in)
    row = hex2dec(state_in{i}(1))+1;
    col = hex2dec(state_in{i}(2))+1;
    state_out(i) = sbox(row,col);
end
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
    % byte_shifted = dec2hex(bitsll(uint8(hex2dec(byte_in)),1),2);    
    byte_shifted = BinToHex(ShiftLeft(HexToBin(byte_in),1,0));
    
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
global mixbox;
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

%% KeySchedule
function expanded_key = KeySchedule(cipher_key)
% Refer to these: 
%   "How to use RCON In Key Expansion of 128 Bit Advanced Encryption Standard"
%      https://crypto.stackexchange.com/questions/2418/how-to-use-rcon-in-key-expansion-of-128-bit-advanced-encryption-standard
%   "Announcing the ADVANCED ENCRYPTION STANDARD (AES)": Appendix A -- Key Expansion Examples
%      http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
%   "The Design of Rijndael": Section 3.6 -- Key Schedule
%      https://link.springer.com/content/pdf/10.1007%2F978-3-662-04722-4.pdf

% ---------- AES-256 ---------- %
Nb = 4;                  % Nb: Block Number
Nr = 14;                 % Nr: Round Number
Nk = 8;                  % Nk: Cipher Key Size
K = cipher_key;          % K : Cipher Key     Nb x Nk     = 4 x 8
W = cell(Nb,Nb*(Nr+1));  % W : Expanded Key   Nb x (Nr+1) = 4 x 15

global RC; % Round Constants

W(1:4,1:8) = K(1:4,1:8);
for col = 9:Nb*(Nr+1)
    if mod(col-1,Nk) == 0
        vec_tmp = circshift(W(:,col-1),-1,1);
        vec_tmp = SubBytes(vec_tmp);
        xor_tmp  = MatrixXor( vec_tmp, W(:,col-Nk) );
        W(:,col) = MatrixXor( xor_tmp, RC(:,(col-1)/Nk) );
    elseif mod(col-1,Nk) == 4
        vec_tmp = W(:,col-1);
        vec_tmp = SubBytes(vec_tmp);
        W(:,col) = MatrixXor( vec_tmp, W(:,col-Nk) );
    else
        vec_tmp = W(:,col-1);
        W(:,col) = MatrixXor( vec_tmp, W(:,col-Nk) );
    end
end
expanded_key = W;
end

%% Mask
function mask = Mask(offset)
global maskbox;
mask = circshift(maskbox,-offset,2);
mask = reshape(mask,4,4);
end

%% MaskedSubBytes
function state_out = MaskedSubBytes(state_in,offset)
state_tmp = MatrixXor(state_in,Mask(offset));
state_tmp = SubBytes(state_tmp);
state_out = MatrixXor(state_tmp,Mask(offset+1)); 
end

%% MaskCompensation
function mask = MaskCompensation(offset)
mask_tmp = Mask(offset);
mask_tmp = ShiftRows(mask_tmp);
mask_tmp = MixColumns(mask_tmp);
mask = MatrixXor(mask_tmp,Mask(offset));
end

%% MaskCompensationLastRound
function mask = MaskCompensationLastRound(offset)
mask_tmp = Mask(offset);
mask_tmp = ShiftRows(mask_tmp);
mask = mask_tmp;
end


