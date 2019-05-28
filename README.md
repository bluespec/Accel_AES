# Accel_AES

Note: under construction (May 28, 2019)

This is a hardware IP, a hardware implementation of AES (Advanced Encryption Standard).  The hardware is designed in the High-Level Hardware Design Language Bluesec BSV, but this repo also contains pre-generated Verilog that can be used immediately as-is.

The IP consists of 3 layers:

2. AXI4 master and slave adapter
1. Generic Memory-to-Memory AES accelerator
0. AES core

Layer 0 is the inner-most layer (AES core) is just a hardware implementation of AES.  Conceptually, it is an object with 3 methods:

- set key    (currently only 128-bit keys; future 192 and 256)
- encrypt a block (128-bit)
- decrypt a block (128-bit)

Layer 1 uses Layer 0 to implement a memory-to-memory functionality with memory master and slave interfaces that are completely generic (no specific bus protocol).  It can be programmed by reading/writing memory-mapped registers on slave interface:

- Write memory address of key
- Write memory address of input text
- Write memory address of output text
- Write number of 128-bit blocks in input/output text
- Write command: expand key/ encrypt/ decrypt
- Read status: idle/ busy/ errors

Once programmed and given a comand, the IP uses the master interface to read and write data from memory, performing the command (key expansion, encryption or decryption).

Layer 2 adapts the generic memory slave and master interfaces in Layer 1 into a 64-bit AXI4 slave and master, respectively.  By replacing Layer2, the core can be used with other buses.
