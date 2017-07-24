%
% Framework for developping attacks in Matlab under Windows
% for the DPA contest V4, AES256 RSM implementation
%
% Requires the wrapper tool for Windows
%
% Version 1,   29/07/2013
% Version 1.0, 03/12/2013 @ SJTU
% Version 2.0, 20/12/2013 @ SJTU
%
% Guillaume Duc <guillaume.duc@telecom-paristech.fr>
%

% Due to the very long duration of an encryption operation on the smart-card
% (the AES has been coded in C and not in assembly language),
% the traces only cover the first round and the beginning of the second round of the AES.

% The target is an AES-256 but only the first round is provided.
% So, the submissions will be evaluated only on their capability
% to recover the 128 bits of the firstsubkey 
% and not the 256 bits of the main key.

% The subkey used during the first AddRoundKey operation of the AES is numbered 0
% (in fact, this subkey is the first 128 bits of the main encryption key).
% The last subkey for an AES-256 is numbered 14 
% (it is used in the 14th AddRoundKey operation).

% Number of the attacked subkey
attacked_subkey = 0;

% TODO: adapt it
hanmingweight = [ % 0x00 -- 0xFF
    0 1 1 2 1 2 2 3 1 2 2 3 2 3 3 4 ...
    1 2 2 3 2 3 3 4 2 3 3 4 3 4 4 5 ...
    1 2 2 3 2 3 3 4 2 3 3 4 3 4 4 5 ...
    2 3 3 4 3 4 4 5 3 4 4 5 4 5 5 6 ...
    1 2 2 3 2 3 3 4 2 3 3 4 3 4 4 5 ...
    2 3 3 4 3 4 4 5 3 4 4 5 4 5 5 6 ...
    2 3 3 4 3 4 4 5 3 4 4 5 4 5 5 6 ...
    3 4 4 5 4 5 5 6 4 5 5 6 5 6 6 7 ...
    1 2 2 3 2 3 3 4 2 3 3 4 3 4 4 5 ...
    2 3 3 4 3 4 4 5 3 4 4 5 4 5 5 6 ...
    2 3 3 4 3 4 4 5 3 4 4 5 4 5 5 6 ...
    3 4 4 5 4 5 5 6 4 5 5 6 5 6 6 7 ...
    2 3 3 4 3 4 4 5 3 4 4 5 4 5 5 6 ...
    3 4 4 5 4 5 5 6 4 5 5 6 5 6 6 7 ...
    3 4 4 5 4 5 5 6 4 5 5 6 5 6 6 7 ...
    4 5 5 6 5 6 6 7 5 6 6 7 6 7 7 8
    ];
sbox = [ % Decimal Format of the Standard S-Box
     99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118, ...
    202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192, ...
    183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21, ...
      4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117, ...
      9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132, ...
     83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207, ...
    208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168, ...
     81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210, ...
    205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115, ...
     96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219, ...
    224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121, ...
    231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8, ...
    186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138, ...
    112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158, ...
    225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223, ...
    140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22
    ];
mask = [ % Used in RSM
      0  15  54  57  83  92 101 106 149 154 163 172 198 201 240 255
    ];

ssamples     = zeros(1,480);
s2samples    = zeros(1,480);
sd           = zeros(16,256,30);
intermedia   = zeros(16,256);
sintermedia  = zeros(16,256);
s2intermedia = zeros(16,256);
r            = zeros(16,256);

% FIFO filenames (the last argument when launching the
% wrapper should be 'fifo')

 fifo_in_filename   = '\\.\pipe\fifo_from_wrapper';
 fifo_out_filename  = '\\.\pipe\fifo_to_wrapper';


% Open the two communication FIFO
% We have to use the Java interface as the native function fopen from
% Matlab is unable to open FIFO!

fifo_in = java.io.FileInputStream(fifo_in_filename);
fifo_out = java.io.FileOutputStream(fifo_out_filename);

% Retrieve the number of traces

num_traces_b = arrayfun(@(x) fifo_in.read(), 1:4);
num_traces   = num_traces_b(4) * 2^24 + num_traces_b(3) * 2^16 ...
               + num_traces_b(2) * 2^8 + num_traces_b(1);

% Send start of attack string
% attack_wrapper.exe -i 20 -d DPA_contestv4_rsm -x dpav4_rsm_index\dpav4_rsm_index_1000.txt -e v4_RSM fifo

fifo_out.write([10 46 10]);

% Main loop
for iteration = 1:num_traces

    % Read trace
    plaintext  = arrayfun(@(x) fifo_in.read(), 1:16);
    ciphertext = arrayfun(@(x) fifo_in.read(), 1:16);
    offset     = fifo_in.read();
    samples    = arrayfun(@(x) fifo_in.read(), 1:435002); % read samples as unsigned bytes
       
    % read Mask power 16x30 and Sbox power 16x30
    samples = [ % 1x960
        samples(4798:4827)     samples(9140:9169)     samples(13479:13508)   samples(17823:17852) ...
        samples(22163:22192)   samples(26506:26535)   samples(30846:30875)   samples(35189:35218) ...
        samples(39531:39560)   samples(43873:43902)   samples(48212:48241)   samples(52555:52584) ...
        samples(56896:56925)   samples(61239:61268)   samples(65579:65608)   samples(69921:69950) ...
        samples(101572:101601) samples(187071:187100) samples(200732:200761) samples(275720:275759) ...
        samples(256954:256983) samples(180844:180873) samples(203596:203625) samples(217259:217288) ...
        samples(285524:285553) samples(262555:262584) samples(197367:197396) samples(220122:220151) ...
        samples(314093:314122) samples(184206:184235) samples(256253:256282) samples(213892:213921)
    ];

    samples = arrayfun(@(x) typecast(uint8(x),'int8'), samples); % convert to signed bytes
    
    % read Mask power 16x2
    maxpowerDiff = -inf;
    offset = 0;
    for off = -2:5    % can be adjusted
        %off = 1;
        % samplesM: 16*2
        samplesM(1,1)  = samples(8+off);      samplesM(1,2) = samples(20+off);
        samplesM(2,1)  = samples(37+off);     samplesM(2,2) = samples(49+off);
        samplesM(3,1)  = samples(69+off);     samplesM(3,2) = samples(81+off);
        samplesM(4,1)  = samples(97+off);     samplesM(4,2) = samples(109+off);
        samplesM(5,1)  = samples(129+off);    samplesM(5,2) = samples(141+off);
        samplesM(6,1)  = samples(157+off);    samplesM(6,2) = samples(169+off);
        samplesM(7,1)  = samples(188+off);    samplesM(7,2) = samples(200+off);
        samplesM(8,1)  = samples(217+off);    samplesM(8,2) = samples(229+off);
        samplesM(9,1)  = samples(247+off);    samplesM(9,2) = samples(259+off);
        samplesM(10,1) = samples(276+off);   samplesM(10,2) = samples(288+off);
        samplesM(11,1) = samples(308+off);   samplesM(11,2) = samples(320+off);
        samplesM(12,1) = samples(337+off);   samplesM(12,2) = samples(349+off);
        samplesM(13,1) = samples(367+off);   samplesM(13,2) = samples(379+off);
        samplesM(14,1) = samples(396+off);   samplesM(14,2) = samples(408+off);
        samplesM(15,1) = samples(427+off);   samplesM(15,2) = samples(439+off);
        samplesM(16,1) = samples(457+off);   samplesM(16,2) = samples(469+off);

    
    % TODO: put your attack code here
    %
    % Your attack code can use:
    % - plaintext: the plaintext
    % - ciphertext: the ciphertext
    % - offset: the offset (0 unless the wrapper is launched with --provide_offset_v4_rsm)
    % - samples: the samples of the trace
    %
    % And must produce bytes which is a 256 lines x 16 columns array
    % (matrix) where for each byte of the attacked subkey (the columns of
    % the array), all the 256 possible values of this byte are sorted
    % according to their probability (first position: most probable, last:
    % least probable), i.e. if your attack is successful, the value of the
    % key is the first line of the array.
    
    % to find out offset
        for i=1:16
            tmp = samplesM(i,1) - samplesM(i,2) + samplesM(mod(i,16)+1,2) - samplesM(mod(i,16)+1,1);
            if (tmp > maxpowerDiff)
                maxpowerDiff = tmp;
                offset = 16-i;
            end
        end
    end
    
    % offset
    % compute intermedia
    for guesskey=0:255
        for i=1:16
            M_off = mod(offset+i,16)+1;
            tmp = bitxor(plaintext(i),guesskey);
            tmp = bitxor(sbox(tmp+1),mask(M_off));
            intermedia(i,guesskey+1) = hanmingweight(tmp+1);
            for j=1:30
                sd(i,guesskey+1,j) = sd(i,guesskey+1,j) + intermedia(i,guesskey+1) * double(samples(480+j+(i-1)*30));
            end
        end
    end
    sintermedia  =  sintermedia + intermedia;
    s2intermedia = s2intermedia + intermedia.^2;
    
    ssamples  = ssamples  + double(samples(481:960));
    s2samples = s2samples + double(samples(481:960)).^2;
       
    tmpr = zeros(1,30);
    for i=1:16 % Key Length: 128 bits = 16 bytes
        for guesskey=0:255 % 1 byte = 8 bits : Each byte has 256 possibilities
            var_intermedia = ...
                (s2intermedia(i,guesskey+1) - sintermedia(i,guesskey+1)*sintermedia(i,guesskey+1)/iteration) ...
                / iteration;
            if (var_intermedia == 0)
                r(i,guesskey+1) = 0;
            else
                for j=1:30
                    var_samples = ...
                        (s2samples(j+(i-1)*30) - ssamples(j+(i-1)*30) * ssamples(j+(i-1)*30) / iteration) ...
                         / iteration;
                    if (var_samples == 0)
                        tmpr(j) = 0;
                    else
                        tmpr(j) ...
                            = (sd(i,guesskey+1,j) - ssamples(j+(i-1)*30) * sintermedia(i,guesskey+1)/iteration) ...
                            / iteration / sqrt(var_intermedia) / sqrt(var_samples);
                    end
                end
                    r(i,guesskey+1) = max(abs(tmpr));
            end
        end
    end
    
    %bytes = repmat((0:255)', 1, 16);
    [xx bytes] = sort(r','descend');
    bytes = bytes -1;

    % Send result
    fifo_out.write(attacked_subkey);
    fifo_out.write(bytes(:,1));
    fifo_out.write(bytes(:,2));
    fifo_out.write(bytes(:,3));
    fifo_out.write(bytes(:,4));
    fifo_out.write(bytes(:,5));
    fifo_out.write(bytes(:,6));
    fifo_out.write(bytes(:,7));
    fifo_out.write(bytes(:,8));
    fifo_out.write(bytes(:,9));
    fifo_out.write(bytes(:,10));
    fifo_out.write(bytes(:,11));
    fifo_out.write(bytes(:,12));
    fifo_out.write(bytes(:,13));
    fifo_out.write(bytes(:,14));
    fifo_out.write(bytes(:,15));
    fifo_out.write(bytes(:,16));
end

% compute corrlation
% Close the two FIFOs
fifo_in.close();
fifo_out.close();
