%
% Framework for developping attacks in Matlab under Windows
% for the DPA contest V4, AES256 RSM implementation
%
% Requires the wrapper tool for Windows
%
% Version 1, 29/07/2013
%
% Guillaume Duc <guillaume.duc@telecom-paristech.fr>
%

% Number of the attacked subkey
% TODO: adapt it
attacked_subkey = 0;


% FIFO filenames (the last argument when launching the
% wrapper should be 'fifo')

fifo_in_filename = '\\.\pipe\fifo_from_wrapper';
fifo_out_filename = '\\.\pipe\fifo_to_wrapper';


% Open the two communication FIFO
% We have to use the Java interface as the native function fopen from
% Matlab is unable to open FIFO!

fifo_in = java.io.FileInputStream(fifo_in_filename);
fifo_out = java.io.FileOutputStream(fifo_out_filename);

% Retrieve the number of traces

num_traces_b = arrayfun(@(x) fifo_in.read(), 1:4);
num_traces = num_traces_b(4) * 2^24 + num_traces_b(3) * 2^16 + num_traces_b(2) * 2^8 + num_traces_b(1);

% Send start of attack string

fifo_out.write([10 46 10]);


% Main loop
for iteration = 1:num_traces

    % Read trace
    plaintext = arrayfun(@(x) fifo_in.read(), 1:16);
    ciphertext = arrayfun(@(x) fifo_in.read(), 1:16);
    offset = fifo_in.read();

    samples = arrayfun(@(x) fifo_in.read(), 1:435002); % read samples as unsigned bytes
    samples = arrayfun(@(x) typecast(uint8(x),'int8'), samples); % convert to signed bytes

    
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
    
    bytes = repmat((0:255)', 1, 16);
    
    
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

% Close the two FIFOs
fifo_in.close();
fifo_out.close();
