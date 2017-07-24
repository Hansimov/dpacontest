DPA contest tools
=================

Intro
-----

The aim of the attack wrapper is to launch the attack program, read
traces from a set of traces, give them one by one to the attack
program, retrieve result matrices from the attack program and store
them for later exploitation by the metrics computation tool.


Requirements
------------

These tools was tested on Windows XP but should work on any version of
Windows since Windows 2000.


Use
---

To list the options supported by the wrapper, in a terminal, enter:
attack_wrapper.exe --help

The last argument on the command line must be the name of the prefix
for the fifos names (advice: use 'fifo').

The options of the compute results tool are:

-o, --output=PREFIX	Prefix of the output filenames (default: results)
-h, --help		Print this help message

The remaining arguments on the command line are the *binary* results
produced by one or several iterations of the attack wrapper.


Example
-------

To launch the attack wrapper for the DPA contest v2, on the first key
(number 0), on 20,000 traces stored inside directory
DPA_contest2_public_base_diff_vcc_a128_2009_12_23 and using the index
file DPA_contest2_public_base_index_file. The results will be stored
on file results_k0 with the binary format (this is the format used by
the metrics computation tool):

attack_wrapper.exe -i 20000 -k 0 -o results_k0 -d DPA_contest2_public_base_diff_vcc_a128_2009_12_23 -x DPA_contest2_public_base_index_file -e v2 fifo

To compute the result metrics (given that the attack was launched on
three keys and the results stored, in binary format, into files
results_k[0,1,2]):

compute_results.exe results_k0 results_k1 results_k2

The full instructions are detailed on the DPA contest website.


License
-------

The DPA contest tools (wrapper, compute_results, traces2text) are
distributed under the GNU General Public License version 3 or
later. The source files can be downloaded on the DPA contest website:
http://www.dpacontest.org

These tools use the libbzip2 library (http://www.bzip.org/) which is
copyright (C) 1996-2010 Julian R Seward.


Support
-------

If you have any problem with the compilation or the use of the attack
wrapper, do not hesitate to contact contact@dpacontest.org. Please
give us as much information as possible (architecture, version of the
operating system, complete error log, etc.).
