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
clear;
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
% generate masksubword table
Output_table=cell(1,16);
for i=1:16
    Output_table{i}=zeros(256,256);
end;
masksbox = [
'6c','73','78','74','fd','64','60','ca','3f','0e','68','24','f1','d8','a4','79';
'c5','8d','c6','72','f5','56','48','ff','a2','db','ad','a0','93','ab','7d','cf';
'b8','f2','9c','29','39','30','f8','c3','3b','aa','ea','fe','7e','d7','3e','1a';
'0b','c8','2c','cc','17','99','0a','95','08','1d','8f','ed','e4','28','bd','7a';
'06','8c','23','15','14','61','55','af','5d','34','d9','bc','26','ec','20','8b';
'5c','de','0f','e2','2f','f3','be','54','65','c4','b1','36','45','43','57','c0';
'df','e0','a5','f4','4c','42','3c','8a','4a','f6','0d','70','5f','33','90','a7';
'5e','ac','4f','80','9d','92','37','fa','b3','b9','d5','2e','1f','f0','fc','dd';
'c2','03','1c','e3','50','98','4b','18','cb','a8','71','32','6b','52','16','7c';
'6f','8e','40','d3','2d','25','9f','87','49','e1','b7','1b','d1','51','04','d4';
'ef','3d','35','05','46','09','2b','53','cd','dc','a3','6d','9e','9a','eb','76';
'e8','c7','38','62','82','da','41','a6','63','59','fb','e5','6a','75','a1','07';
'b5','77','2a','21','13','a9','bb','c9','e7','d2','7b','10','44','b2','84','85';
'7f','31','ba','69','47','0c','f9','01','6e','3a','58','b6','89','ce','12','91';
'ee','f7','97','1e','66','d6','81','9b','94','11','88','e6','c1','5a','27','d0';
'83','ae','86','02','b0','e9','4d','67','4e','96','22','00','bf','5b','b4','19';
'40','9d','e1','c8','1d','51','37','06','f3','59','5d','c4','4d','41','4a','55';
'f6','44','92','aa','99','94','e2','9b','c6','71','6f','cc','4b','ff','b4','fc';
'23','07','ee','47','c7','d3','93','02','fa','c1','09','00','10','a5','cb','81';
'43','84','11','dd','d4','b6','24','31','ac','33','a0','2e','f5','15','f1','32';
'b2','19','d5','1f','85','e0','0d','64','96','6c','58','2d','2c','1a','b5','3f';
'f9','6e','7a','7c','0f','88','fd','5c','6d','87','ca','16','db','36','e7','65';
'9e','a9','0a','66','49','34','cf','73','b3','05','7b','75','cd','9c','d9','e6';
'e4','c5','c9','26','17','ec','80','8a','c3','0e','ab','a4','b9','76','95','67';
'45','2f','6b','52','0b','48','91','f2','21','72','a1','69','da','25','3a','fb';
'ed','3d','68','e8','22','8e','d8','70','be','a6','1c','14','ea','79','b7','56';
'4f','d2','a3','a7','54','9a','e5','f4','6a','12','30','7f','3c','0c','04','d6';
'3e','98','4c','53','dc','c2','60','5a','9f','78','e3','bb','5b','01','fe','d1';
'bc','bd','8b','7d','29','42','eb','de','f0','82','90','2a','18','13','4e','8c';
'a8','2b','f7','b0','8f','61','03','57','38','c0','35','7e','50','83','08','46';
'e9','1e','63','f8','df','b1','28','ad','a2','b8','ef','5f','27','ae','ce','d7';
'20','8d','62','86','39','1b','af','77','5e','74','d0','89','3b','bf','97','ba';
'3c','a3','21','af','1a','fa','3d','fe','8b','4c','d2','1e','b9','db','3e','2b';
'ce','f5','0f','06','aa','1f','8e','c4','08','2c','48','e1','dc','c8','0d','9c';
'7e','c9','c3','60','f0','44','f3','bb','4b','f9','a5','9d','9b','96','94','ed';
'56','fc','cb','52','4e','42','5a','45','92','4f','c7','ee','5e','12','09','38';
'01','cc','ab','a4','79','b6','68','9a','ca','eb','29','c6','e3','18','85','8f';
'0a','bc','7a','74','93','c2','e9','d6','a6','91','69','05','3b','46','7c','c0';
'88','62','19','c5','39','d4','6a','e8','61','f6','73','75','87','00','53','f2';
'63','99','22','57','15','23','30','ba','16','bd','10','da','ef','8a','6b','02';
'77','90','b4','ec','0e','54','de','f1','97','31','5c','43','cd','d3','55','6f';
'1d','65','70','3f','03','33','d9','0b','dd','40','a8','ac','95','5b','fb','ea';
'a9','b1','1b','13','76','e5','59','b8','32','e2','e7','67','81','2d','7f','d7';
'7d','2e','66','ae','2a','d5','f4','35','20','4a','5d','64','47','04','fd','9e';
'7b','51','86','df','b0','34','b5','98','82','2f','89','6d','14','36','78','a0';
'b7','ad','50','e0','a1','28','d8','c1','11','e6','f7','6c','be','d0','a2','27';
'cf','37','71','3a','8c','5f','49','07','24','a7','bf','f8','6e','80','58','0c';
'8d','ff','25','9f','1c','17','83','41','b2','b3','72','84','4d','26','d1','e4';
'41','54','b1','d3','74','b8','26','e1','94','57','90','70','c5','4b','c9','56';
'f6','67','a2','b6','8b','22','46','62','ae','e4','75','c0','6c','65','9f','a4';
'87','fe','fc','f1','f7','cf','93','21','d1','99','2e','9a','0a','a9','a3','14';
'52','63','78','34','84','ad','25','f8','2f','30','28','24','38','a1','96','3c';
'e5','ef','72','89','ac','43','81','a0','f0','02','dc','13','ce','c1','a6','6b';
'aa','16','2c','51','6f','03','fb','cc','bc','83','a8','f9','1e','10','d6','60';
'98','39','6a','ed','1f','19','9c','0b','82','00','be','53','af','73','08','e2';
'68','01','e0','85','b0','7a','d7','7c','d0','5a','49','7f','3d','48','f3','09';
'05','3f','b9','a7','29','36','5b','fd','9b','b4','3e','64','86','de','fa','1d';
'80','91','31','ff','c6','c2','2a','b7','61','b3','59','69','55','1a','0f','77';
'bd','15','47','eb','0d','8d','88','58','d2','33','8f','1c','79','71','db','c3';
'f4','97','6e','2d','0e','37','20','4a','5f','9e','bf','40','c4','0c','44','17';
'ca','12','5c','7e','07','e3','45','e8','f2','df','5e','da','b5','ec','3b','11';
'4d','c8','ba','d4','06','9d','8c','7b','ab','b2','42','cb','8a','3a','c7','dd';
'66','32','ea','04','92','d5','cd','4e','6d','23','35','e6','50','1b','5d','a5';
'8e','bb','4c','27','ee','18','d9','d8','2b','e9','7d','76','f5','4f','95','e7';
'b1','5c','8d','0f','07','ed','a0','7c','65','e2','97','36','93','04','10','16';
'46','70','df','55','fc','06','32','47','ef','8a','67','0e','d8','73','bf','75';
'd3','1c','ff','0d','a9','64','c1','ce','7d','86','ea','e0','8e','af','a3','4c';
'a7','f6','b3','8c','d9','6f','11','1f','23','5e','a5','19','f4','c3','60','0c';
'21','95','de','96','ac','1b','05','a6','f3','fe','88','f1','9c','2e','f8','c0';
'27','2b','20','3f','99','33','37','ae','77','3b','5d','6c','2a','f7','8b','a2';
'9f','7f','9b','58','c6','59','ca','44','be','dc','4e','5b','29','ee','7b','b7';
'7a','cf','a1','eb','90','ab','63','6a','ad','b9','f9','68','49','6d','84','2d';
'3a','e9','62','2c','52','aa','5f','14','e5','0b','69','3d','c2','41','9d','da';
'72','79','24','e6','9a','e8','fa','40','43','28','81','b4','d6','d7','e1','17';
'51','d5','fd','d0','34','1e','ba','e3','53','71','c5','1d','4a','e7','08','ec';
'4d','c4','a4','bd','c8','d2','85','35','b5','db','42','c7','83','74','09','92';
'80','13','dd','3c','d4','cc','76','7e','48','e4','b2','1a','87','57','02','82';
'b0','4f','50','91','4b','18','cb','03','61','22','fb','98','2f','45','01','38';
'31','6b','94','bb','f5','12','89','d1','b6','a8','0a','30','54','f2','26','39';
'56','66','6e','bc','00','78','5a','15','3e','f0','8f','9e','25','b8','c9','cd';
'2f','29','3d','aa','0f','ae','db','5c','45','99','d4','3e','36','b4','65','88';
'4c','86','4a','e1','37','5e','b3','d6','7e','0b','3f','c5','6c','e6','49','7f';
'75','9a','96','b7','d9','d3','bf','44','f7','f8','5d','90','34','c6','25','ea';
'35','59','fa','cd','20','9c','67','1a','26','28','56','e0','b5','8a','cf','9e';
'f9','c1','17','a5','c8','b1','c7','ca','9f','3c','22','95','af','e7','ac','18';
'9b','b2','ce','13','55','64','02','4e','97','0e','0a','a0','06','19','12','1e';
'8e','42','d7','10','62','77','e5','87','7d','f3','60','ff','61','a2','46','a6';
'14','bd','54','70','51','c0','80','94','53','5a','92','a9','d2','98','f6','43';
'e3','a4','78','fb','04','50','32','dc','2d','66','93','6b','15','5b','d0','03';
'2e','d8','ee','ef','8d','b8','11','7a','79','c3','d1','a3','df','1d','40','4b';
'd5','31','de','73','24','fc','48','6a','da','83','27','0d','e9','c4','ec','68';
'ab','30','4d','ba','fe','7b','e2','8c','0c','bc','eb','f1','84','9d','fd','74';
'bb','3b','6e','be','23','8b','dd','71','47','4f','f5','ed','05','e4','2a','b9';
'01','38','7c','16','a1','c2','1b','58','3a','f2','21','72','a8','69','76','89';
'00','1f','cb','6d','09','33','91','8f','e8','b0','2b','cc','82','ad','52','08';
'f4','f0','81','1c','a7','b6','c9','07','2c','63','41','39','85','57','5f','6f';
'27','29','ef','59','85','ba','91','c0','56','3a','c2','f5','93','2f','15','68';
'f7','f8','9f','52','c9','3b','e5','2a','95','7a','b8','99','dc','d6','4b','b0';
'04','71','ca','30','e9','63','70','46','89','43','ee','45','51','38','d9','bc';
'96','4a','31','db','bb','39','87','6a','26','20','a5','32','a1','00','53','d4';
'55','5c','a6','9d','97','dd','4c','f9','b2','1b','7f','5b','cf','5e','9b','8f';
'fc','72','f0','6f','ad','6e','a9','49','4d','81','1f','d8','78','6d','88','ea';
'01','98','af','05','16','09','11','1d','bd','94','1c','c1','6b','5a','41','0d';
'33','90','9a','2d','e8','a0','17','a3','ce','f6','aa','18','be','c7','c5','c8';
'b3','03','fe','e4','92','8b','7b','f2','3f','a4','b5','42','74','f1','83','ed';
'8c','d5','02','28','cb','e6','67','e3','3e','da','7c','d1','f3','2b','65','47';
'cc','76','ac','de','12','d0','44','4f','d7','21','e0','e1','b7','82','75','1e';
'69','22','64','9c','54','1a','0c','df','ab','ec','f4','77','5f','0b','d3','3d';
'6c','23','36','4e','58','8a','60','50','ff','fb','13','8e','b9','a8','08','c6';
'bf','e7','c3','24','a2','8d','07','5d','10','0f','62','c4','3c','06','80','9e';
'fd','35','7d','2e','66','a7','86','79','37','0e','19','73','cd','ae','57','14';
'40','48','e2','fa','eb','0a','b6','25','34','b4','b1','61','84','2c','7e','d2';
'97','ea','d0','6c','0a','3d','c5','a9','3f','6e','45','7a','a6','10','d6','d8';
'4f','b4','29','23','66','47','85','6a','d5','1a','c4','36','ad','60','07','08';
'43','26','c7','ae','ba','11','bc','76','b9','8f','9c','16','cf','35','8e','fb';
'2b','ac','ff','5e','cd','5a','df','d9','95','78','c6','44','24','ce','b5','69';
'70','64','a1','30','a4','80','e4','4d','06','b3','22','68','62','59','a3','aa';
'15','77','92','87','27','e0','7e','b2','b6','56','91','52','90','0f','8d','03';
'f2','be','a5','94','3e','e3','6b','42','e2','ee','f6','e9','fa','50','67','fe';
'37','3a','38','41','e7','55','09','31','5c','e8','5f','17','d2','65','6f','cc';
'12','7c','0e','8b','bd','4a','5b','c0','0d','84','74','6d','1b','01','fc','4c';
'b8','9a','d4','0c','2e','83','25','c1','1c','98','19','34','d7','fd','2a','73';
'e1','8a','7d','48','1e','1f','de','28','b0','bb','2f','ed','21','53','89','33';
'c2','2c','f4','a0','88','0b','13','54','20','f3','e5','ab','63','9b','dd','96';
'39','f7','57','46','71','ec','04','00','af','9f','75','a7','b1','c9','dc','93';
'61','7f','f9','c3','3b','9d','f0','ef','a2','f8','72','5d','db','3c','18','40';
'eb','a8','51','32','8c','e6','f1','c8','86','79','58','99','d1','82','ca','02';
'2d','81','d3','7b','9e','4e','4b','cb','da','49','f5','14','05','1d','b7','bf';
'b0','b8','12','0a','1b','fa','46','d5','c4','44','41','91','74','dc','8e','22';
'0d','c5','8d','de','96','57','76','89','c7','fe','e9','83','3d','5e','a7','e4';
'4f','17','33','d4','52','7d','f7','ad','e0','ff','92','34','cc','f6','70','6e';
'9c','d3','c6','be','a8','7a','90','a0','0f','0b','e3','7e','49','58','f8','36';
'99','d2','94','6c','a4','ea','fc','2f','5b','1c','04','87','af','fb','23','cd';
'3c','86','5c','2e','e2','20','b4','bf','27','d1','10','11','47','72','85','ee';
'7c','25','f2','d8','3b','16','97','13','ce','2a','8c','21','03','db','95','b7';
'43','f3','0e','14','62','7b','8b','02','cf','54','45','b2','84','01','73','1d';
'c3','60','6a','dd','18','50','e7','53','3e','06','5a','e8','4e','37','35','38';
'f1','68','5f','f5','e6','f9','e1','ed','4d','64','ec','31','9b','aa','b1','fd';
'0c','82','00','9f','5d','9e','59','b9','bd','71','ef','28','88','9d','78','1a';
'a5','ac','56','6d','67','2d','bc','09','42','eb','8f','ab','3f','ae','6b','7f';
'66','ba','c1','2b','4b','c9','77','9a','d6','d0','55','c2','51','f0','a3','24';
'f4','81','3a','c0','19','93','80','b6','79','b3','1e','b5','a1','c8','29','4c';
'07','08','6f','a2','39','cb','15','da','65','8a','48','69','2c','26','bb','40';
'd7','d9','1f','a9','75','4a','61','30','a6','ca','32','05','63','df','e5','98';
'1b','b7','e5','4d','a8','78','7d','fd','ec','7f','c3','22','33','2b','81','89';
'dd','9e','67','04','ba','d0','c7','fe','b0','4f','6e','af','e7','b4','fc','34';
'57','49','cf','f5','0d','ab','c6','d9','94','ce','44','6b','ed','0a','2e','76';
'0f','c1','61','70','47','da','32','36','99','a9','43','91','87','ff','ea','a5';
'f4','1a','c2','96','be','3d','25','62','16','c5','d3','9d','55','ad','eb','a0';
'd7','bc','4b','7e','28','29','e8','1e','86','8d','19','db','17','65','bf','05';
'8e','ac','e2','3a','18','b5','13','f7','2a','ae','2f','02','e1','cb','1c','45';
'24','4a','38','bd','8b','7c','6d','f6','3b','b2','42','5b','2d','37','ca','7a';
'01','0c','0e','77','d1','63','3f','07','6a','de','69','21','e4','53','59','fa';
'c4','88','93','a2','08','d5','5d','74','d4','d8','c0','df','cc','66','51','c8';
'23','41','a4','b1','11','d6','48','84','80','60','a7','64','a6','39','bb','35';
'46','52','97','06','92','b6','d2','7b','30','85','14','5e','54','6f','95','9c';
'1d','9a','c9','68','fb','6c','e9','ef','a3','4e','f0','72','12','f8','83','5f';
'75','10','f1','98','8c','27','8a','40','8f','b9','aa','20','f9','03','b8','cd';
'79','82','1f','15','50','71','b3','5c','e3','2c','f2','00','9b','56','31','3e';
'a1','dc','e6','5a','3c','0b','f3','9f','09','58','73','4c','90','26','e0','ee';
'a6','96','9e','4c','f0','88','aa','e5','ce','00','7f','6e','d5','48','39','3d';
'c1','9b','64','4b','05','e2','79','21','46','58','fa','c0','a4','02','d6','c9';
'40','bf','a0','61','bb','e8','3b','f3','91','d2','0b','68','df','b5','f1','c8';
'70','e3','2d','cc','24','3c','86','8e','b8','14','42','ea','77','a7','f2','72';
'bd','34','54','4d','38','22','75','c5','45','2b','b2','37','73','84','f9','62';
'a1','25','0d','20','c4','ee','4a','13','a3','81','35','ed','ba','17','f8','1c';
'82','89','d4','16','6a','18','0a','b0','b3','d8','71','44','26','27','11','e7';
'ca','19','92','dc','a2','5a','af','e4','15','fb','99','cd','32','b1','6d','2a';
'8a','3f','51','1b','60','5b','93','9a','5d','49','09','98','b9','9d','74','dd';
'6f','8f','6b','a8','36','a9','3a','b4','4e','2c','be','ab','d9','1e','8b','47';
'd7','db','d0','cf','69','c3','c7','5e','87','cb','ad','9c','da','07','7b','52';
'd1','65','2e','66','5c','eb','f5','56','03','0e','78','01','6c','de','08','30';
'57','06','43','7c','29','9f','e1','ef','d3','ae','55','e9','04','33','90','fc';
'23','ec','0f','fd','59','94','31','3e','8d','76','1a','10','7e','5f','53','bc';
'b6','80','2f','a5','0c','f6','c2','b7','1f','7a','97','fe','28','83','4f','85';
'41','ac','7d','ff','f7','1d','50','8c','95','12','67','c6','63','f4','e0','e6';
'57','53','22','bf','04','15','6a','a4','8f','c0','e2','9a','26','f4','fc','cc';
'a3','bc','68','ce','aa','90','32','2c','4b','13','88','6f','21','0e','f1','ab';
'a2','9b','df','b5','02','61','b8','fb','99','51','82','d1','0b','ca','d5','2a';
'18','98','cd','1d','80','28','7e','d2','e4','ec','56','4e','a6','47','89','1a';
'08','93','ee','19','5d','d8','41','2f','af','1f','48','52','27','3e','5e','d7';
'76','92','7d','d0','87','5f','eb','c9','79','20','84','ae','4a','67','4f','cb';
'8d','7b','4d','4c','2e','1b','b2','d9','da','60','72','00','7c','be','e3','e8';
'40','07','db','58','a7','f3','91','7f','8e','c5','30','c8','b6','f8','73','a0';
'b7','1e','f7','d3','f2','63','23','37','f0','f9','31','0a','71','3b','55','e0';
'2d','e1','74','b3','c1','d4','46','24','de','50','c3','5c','c2','01','e5','05';
'38','11','6d','b0','f6','c7','a1','ed','34','ad','a9','03','a5','ba','b1','bd';
'5a','62','b4','06','6b','12','64','69','3c','9f','81','36','0c','44','0f','bb';
'96','fa','59','6e','83','3f','c4','b9','85','8b','f5','43','16','29','6c','3d';
'd6','39','35','14','7a','70','1c','e7','54','5b','fe','33','97','65','86','49';
'ef','25','e9','42','94','fd','10','75','dd','a8','9c','66','cf','45','ea','dc';
'8c','8a','9e','09','ac','0d','78','ff','e6','3a','77','9d','95','17','c6','2b';
'7d','0f','d5','6f','ec','e7','73','b1','42','43','82','74','bd','d6','21','14';
'3f','c7','81','ca','7c','af','b9','f7','d4','57','4f','08','9e','70','a8','fc';
'47','5d','a0','10','51','d8','28','31','e1','16','07','9c','4e','20','52','d7';
'8b','a1','76','2f','40','c4','45','68','72','df','79','9d','e4','c6','88','50';
'8d','de','96','5e','da','25','04','c5','d0','ba','ad','94','b7','f4','0d','6e';
'59','41','eb','e3','86','15','a9','48','c2','12','17','97','71','dd','8f','27';
'ed','95','80','cf','f3','c3','29','fb','2d','b0','58','5c','65','ab','0b','1a';
'87','60','44','1c','fe','a4','2e','01','67','c1','ac','b3','3d','23','a5','9f';
'93','69','d2','a7','e5','d3','c0','4a','e6','4d','e0','2a','1f','7a','9b','f2';
'78','92','e9','35','c9','24','9a','18','91','06','83','85','77','f0','a3','02';
'fa','4c','8a','84','63','32','19','26','56','61','99','f5','cb','b6','8c','30';
'f1','3c','5b','54','89','46','98','6a','3a','1b','d9','36','13','e8','75','7f';
'a6','0c','3b','a2','be','b2','aa','b5','62','bf','37','1e','ae','e2','f9','c8';
'8e','39','33','90','00','b4','03','4b','bb','09','55','6d','6b','66','64','1d';
'3e','05','ff','f6','5a','ef','7e','34','f8','dc','b8','11','2c','38','fd','6c';
'cc','53','d1','5f','ea','0a','cd','0e','7b','bc','22','ee','49','2b','ce','db';
'2d','18','ef','84','4d','bb','7a','7b','88','4a','de','d5','56','ec','36','44';
'c5','91','49','a7','31','76','6e','ed','ce','80','96','45','f3','b8','fe','06';
'ee','6b','19','77','a5','3e','2f','d8','08','11','e1','68','29','99','64','7e';
'69','b1','ff','dd','a4','40','e6','4b','51','7c','fd','79','16','4f','98','b2';
'57','34','cd','8e','ad','94','83','e9','fc','3d','1c','e3','67','af','e7','b4';
'1e','b6','e4','48','ae','2e','2b','fb','71','90','2c','bf','da','d2','78','60';
'23','32','92','5c','65','61','89','14','c2','10','fa','ca','f6','b9','ac','d4';
'a6','9c','1a','04','8a','95','f8','5e','38','17','9d','c7','25','7d','59','be';
'cb','a2','43','26','13','d9','74','df','73','f9','ea','dc','9e','eb','50','aa';
'3b','9a','c9','4e','bc','ba','3f','a8','21','a3','1d','f0','0c','d0','ab','41';
'09','b5','8f','f2','cc','a0','58','6f','1f','20','0b','5a','bd','b3','75','c3';
'46','4c','d1','2a','0f','e0','22','03','53','a1','7f','b0','6d','62','05','c8';
'f1','c0','db','97','27','0e','86','5b','8c','93','8b','87','9b','02','35','9f';
'24','5d','5f','52','54','6c','30','82','72','3a','8d','39','a9','0a','00','b7';
'55','c4','01','15','28','81','e5','c1','0d','47','d6','63','cf','c6','3c','07';
'e2','f7','12','70','d7','1b','85','42','37','f4','33','d3','66','e8','6a','f5';
'73','5e','76','f2','40','19','bd','97','be','66','d2','f0','4f','ab','44','e9';
'1e','07','67','ee','96','26','71','6b','64','e1','78','16','31','aa','d7','20';
'8f','c1','4a','99','b7','fc','09','f1','9e','ca','a8','46','79','3e','e2','61';
'45','87','da','d1','e3','59','4b','39','17','22','8b','e0','b4','42','74','75';
'18','37','c8','92','72','2a','b1','56','93','a9','0b','15','9a','85','51','f7';
'1f','cd','c5','f5','b6','f9','db','a3','3d','2c','53','9d','6e','6a','1b','86';
'9f','7e','b0','23','dd','d5','6f','77','b9','11','47','eb','21','a1','f4','24';
'32','f3','ec','13','a0','68','bb','e8','3b','58','81','c2','9b','a2','e6','8c';
'ae','5c','bf','70','6d','62','c7','0a','43','49','25','de','ef','00','0c','2d';
'2f','10','55','04','bc','b2','cc','7a','ba','06','fd','80','af','c3','60','57';
'ac','2e','ff','12','df','03','4e','a4','95','34','41','c6','b5','b3','a7','30';
'f6','7c','d3','e5','e4','91','a5','5f','ad','c4','29','4c','d6','1c','d0','7b';
'fb','38','dc','3c','e7','69','fa','65','f8','ed','7f','1d','14','d8','4d','8a';
'48','02','6c','d9','c9','c0','08','33','cb','5a','1a','0e','8e','27','ce','ea';
'35','7d','36','82','05','a6','b8','0f','52','2b','5d','50','63','5b','8d','3f';
'9c','83','88','84','0d','94','90','3a','cf','fe','98','d4','01','28','54','89';
'16','bb','54','b0','0f','2d','99','41','68','42','e6','bf','0d','89','a1','8c';
'df','28','55','ce','e9','87','1e','9b','94','8e','d9','69','11','98','f8','e1';
'9e','1d','c1','86','b9','57','35','61','0e','f6','03','48','66','b5','3e','70';
'8a','8b','bd','4b','1f','74','dd','e8','c6','b4','a6','1c','2e','25','78','ba';
'08','ae','7a','65','ea','f4','56','6c','a9','4e','d5','8d','6d','37','c8','e7';
'79','e4','95','91','62','ac','d3','c2','5c','24','06','49','0a','3a','32','e0';
'db','0b','5e','de','14','b8','ee','46','88','90','2a','22','dc','4f','81','60';
'73','19','5d','64','3d','7e','a7','c4','17','44','97','5f','ec','13','0c','cd';
'd2','f3','ff','10','21','da','b6','bc','f5','38','9d','92','8f','40','a3','51';
'a8','9f','3c','50','7f','02','f9','45','85','33','4d','43','fb','aa','ef','d0';
'cf','58','4c','4a','39','be','cb','6a','5b','b1','fc','20','ed','00','d1','53';
'84','2f','e3','29','b3','d6','3b','52','a0','5a','6e','1b','1a','2c','83','09';
'75','b2','27','eb','e2','80','12','07','9a','05','96','18','c3','23','c7','04';
'15','31','d8','71','f1','e5','a5','34','cc','f7','3f','36','26','93','fd','b7';
'c0','72','a4','9c','af','a2','d4','ad','f0','47','59','fa','7d','c9','82','ca';
'76','ab','d7','fe','2b','67','01','30','c5','6f','6b','f2','7b','77','7c','63';];
M=['00', '0f', '36', '39', '53','5c', '65', '6a','95', '9a', 'a3', 'ac', 'c6', 'c9', 'f0', 'ff'];
for i=1:16
    for j=1:256
        for k=1:256
                n=0;
                m=hex2dec(M(2*i-1:i*2));
                b=bitxor(m,j-1);
                b=bitxor(b,k-1);
                s1=floor(b/16)+1;
                s2=mod(b,16)+1;
                ind=16*mod(i-1,16);
                x=adz(h2b(masksbox(ind+s1,2*s2-1:2*s2)),8);
                for y=1:8
                    if(x(y)=='1')
                         n=n+1;
                    end
                end
                Output_table{i}(j,k)=n;
        end;
    end
end

fifo_out.write([10 46 10]);
offPoint=zeros(num_traces,16);
keyPointPlus=zeros(num_traces,16);
keyPointMinus=zeros(num_traces,16);
offCorr=zeros(1,16);
corr=zeros(256,16);
offHw=[0,4,4,4,4,4,4,4,4,4,4,4,4,4,4,8;4,4,4,4,4,4,4,4,4,4,4,4,4,4,8,0;4,4,4,4,4,4,4,4,4,4,4,4,4,8,0,4;4,4,4,4,4,4,4,4,4,4,4,4,8,0,4,4;4,4,4,4,4,4,4,4,4,4,4,8,0,4,4,4;4,4,4,4,4,4,4,4,4,4,8,0,4,4,4,4;4,4,4,4,4,4,4,4,4,8,0,4,4,4,4,4;4,4,4,4,4,4,4,4,8,0,4,4,4,4,4,4;4,4,4,4,4,4,4,8,0,4,4,4,4,4,4,4;4,4,4,4,4,4,8,0,4,4,4,4,4,4,4,4;4,4,4,4,4,8,0,4,4,4,4,4,4,4,4,4;4,4,4,4,8,0,4,4,4,4,4,4,4,4,4,4;4,4,4,8,0,4,4,4,4,4,4,4,4,4,4,4;4,4,8,0,4,4,4,4,4,4,4,4,4,4,4,4;4,8,0,4,4,4,4,4,4,4,4,4,4,4,4,4;8,0,4,4,4,4,4,4,4,4,4,4,4,4,4,4;];
hw=zeros(num_traces,256,16);
%hw=zeros(num_traces,key_guess,byte);
indMinus=[1577,39670,6339,44432,11100,49190,15861,53954,20623,58714,25385,63478,30145,68231,34628,73981;];
indPlus=[1590,39681,6357,44424,11113,49204,15593,53944,20635,58705,25117,63469,30159,68248,34641,73288;];
offInd=[4805,9146,13485,17829,22168,26512,30851,35195,39537,43878,48216,52561,56902,61244,65585,69927];
HW_table = [0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8;];
indPlus=indPlus+100000; 
indMinus=indMinus+100000;
 % Main loop
for iteration = 1:num_traces

    % Read trace
    plaintext = arrayfun(@(x) fifo_in.read(), 1:16);
    ciphertext = arrayfun(@(x) fifo_in.read(), 1:16);
    offset = fifo_in.read();

    samples = arrayfun(@(x) fifo_in.read(), 1:435002); % read samples as unsigned bytes
    samples = arrayfun(@(x) typecast(uint8(x),'int8'), samples(1:175000)); % convert to signed bytes
    
     
    
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
    
    %start guess offset
    offPoint(iteration,:) = samples(1,offInd);
    for i=1:16
        temp = corrcoef(offHw(:,i),offPoint(iteration,:));
        offCorr(1,i) = temp(1,2);
    end
    [Value Order]=sort(offCorr);
    offset=Order(1,16);
    
    bytes = repmat((0:255)', 1, 16);
    %start guess key
    
    keyPointPlus(iteration,:)=samples(indPlus);
    keyPointMinus(iteration,:)=samples(indMinus);
    for i=1:16
        x=plaintext(1,i)+1;
        maskind=mod(i+offset-2,16)+1;
        hw(iteration,:,i)=Output_table{maskind}(x,:);
        for j=1:256
            corrPlus=corrcoef(hw(1:iteration,j,i),keyPointPlus(1:iteration,i));
            corrMinus=corrcoef(hw(1:iteration,j,i),keyPointMinus(1:iteration,i));
            if(iteration==1)
                corr(j,i)=j;
            else
                corr(j,i)=-corrPlus(1,2)+corrMinus(1,2);
            end
        end
        [temp bytes(:,i)]=sort(corr(:,i));
        clear temp;
        bytes(:,i)=bytes(:,i)-1;
    end
   
    
    
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
