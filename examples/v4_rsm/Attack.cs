/*
 * Template for developing attacks in C# under Windows
 *
 * Template for DPA contest v4 AES-256 RSM implementation
 */

using System;
using System.IO;
using System.IO.Pipes;

class Attack
{
  NamedPipeClientStream output_fifo;
  NamedPipeClientStream input_fifo;

  byte attacked_subkey; // The attacked subkey number

  uint num_traces; // Number of traces that will be sent by the wrapper

  byte[] plaintext; // The plaintext of the current trace
  byte[] ciphertext; // The ciphertext of the current trace
  byte offset; // The offset used for the current trace if option --provide_offset_v4_rsm is given to the wrapper
  sbyte[] samples; // The samples of the trace (-128..127)

  byte[][] results; // The bi-dimensional array containing the partial results

  byte[] samples_b;


  public Attack()
  {
    // TODO: Modify the subkey number if necessary
    attacked_subkey = 0;

    plaintext = new byte[16];
    ciphertext = new byte[16];
    samples = new sbyte[435002];
    samples_b = new byte[435002];

    results = new byte[16][];
    for (int i = 0; i < 16; i++)
      results[i] = new byte[256];
  }

  public void Read(byte[] dest, int count)
  {
    int bytes_read = 0;
    int total_bytes_read = 0;

    while (total_bytes_read < count)
      {
	bytes_read = input_fifo.Read(dest, total_bytes_read, (count - total_bytes_read));
	total_bytes_read += bytes_read;
      }
  }

  public void Write(byte[] source, int count)
  {
    output_fifo.Write(source, 0, count);
    output_fifo.Flush();
  }

  public void LaunchAttack()
  {
    // Open the FIFOs
    input_fifo = new NamedPipeClientStream(".", "fifo_from_wrapper", PipeDirection.In);
    output_fifo = new NamedPipeClientStream(".", "fifo_to_wrapper", PipeDirection.Out);

    input_fifo.Connect();
    output_fifo.Connect();

    // Receive the number of traces;
    byte[] num_traces_a = new byte[4];
    Read(num_traces_a, 4);

    num_traces = (((uint) num_traces_a[3]) << 24) 
      + (((uint) num_traces_a[2]) << 16)
      + (((uint) num_traces_a[1]) << 8)
      + num_traces_a[0];

    // Send start of attack
    byte[] start_seq = {0x0A, 0x2E, 0x0A};
    Write (start_seq, 3);

    // Main loop
    for (uint trace_num = 0; trace_num < num_traces; trace_num++)
      {
	// Read the plaintext, ciphertext and offset
	Read(plaintext, plaintext.Length);
	Read(ciphertext, ciphertext.Length);
	offset = (byte) input_fifo.ReadByte();

	// Read the samples
	Read(samples_b, samples_b.Length);

	// Convert the samples to signed bytes
	for (uint index = 0; index < samples.Length; index++)
	  {
	    unchecked
	      {
		samples[index] = (sbyte) samples_b[index];
	      }
	  }


	// TODO: put your attack code here
	//
	// Your attack code can use:
	// - plaintext: the plaintext
	// - ciphertext: the ciphertext
	// - offset: the offset (0 unless the wrapper is launched with --provide_offset_v4_rsm)
	// - samples: the samples of the trace
	//
	// And must fill the result bi-dimensional (16*256) array
	// For i in [0..15], results[i] contains all the 256 possible values for the byte
	// i of the attacked subkey sorted according to their probability (index 0: most probable,
	// index 255: least probable)
	for (int byte_num = 0; byte_num < 16; byte_num++)
	  for (int val = 0; val < 256; val++)
	    results[byte_num][val] = (byte) val;


	// Send the results
	output_fifo.WriteByte(attacked_subkey);
	for (int index = 0; index < 16; index++)
	  Write(results[index], 256);
      }

    // Close the FIFOs
    output_fifo.Close();
    input_fifo.Close();
  }

  public static void Main()
  {
    Attack attack = new Attack();

    attack.LaunchAttack();
  }
}
