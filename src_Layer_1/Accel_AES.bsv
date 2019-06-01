// Copyright (c) 2019 Bluespec, Inc. All Rights Reserved.
// Author: Rishiyur S. Nikhil

package Accel_AES;

// ================================================================
// This is a wrapper for the core AES hardware, converting it into an
// IP block for an SoC so it can behave as a memory-to-memory AES
// accelerator.

// The interface here is a generic master and slave, and not for any
// specific SoC fabric. It will have to be adapted for particular SoC
// fabrics (such as AXI4, AXI4_Lite, ...).

// The CPU configures and queries the accelerator by reading and
// writing 64-bit configuration registers via the slave port.  These
// are memory-mapped, starting at a configurable base address.
//
//   [0]: Command (see command list below)
//   [1]: Status port (see status list below)
//   [2]: memory address of 128b AES key
//   [3]: memory address of source text buffer (N x 128b blocks)
//   [4]: memory address of target text buffer (N x 128b blocks)
//   [5]: N (# of 128-bit blocks to encrypt/decrypt)
//
// Commands: writes into base_addr[0] are commands:
//   0: ignored
//   1: 'do key expansion'
//   2: 'encrypt from source to target'
//   3: 'decrypt from source to target'

// Status: reads from base_addr[1] return status:
//   => 0: Idle (last key expansion/encryption/decryption completed)
//   => 1: Still busy with last command (key expansion/encryption/decryption)
//   => 10: Command error: unrecognized command
//   => 11: Slave address error: unrecognized or misaligned address

// ================================================================
// Note about byte order in memory:
// In NIST FIPS 197
// (National Institute of Standards and Technology
//  Federal Information Processing Standards Publication 197),
// The bytes of keys and data are listed in a certain order.
// E.g., "Appendix B - Cipher Example" shows:
//   Input      = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
//   Cipher Key = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

// The SW preference seems to be to lay the bytes out in memory in
// this left-to-right order, i.e., bytes '32' and '2b' are at
// byte-offset 0, and bytes '34' and '3c' are at offset 15,
// respectively.  This is a 'big-endian' order when viewing the Input
// and Key as 128b numbers.  This is taken into account below in the
// FSMs that read four 32b words from memory and assemble a 128b
// value.

// ================================================================
// Exports

export
Accel_AES_IFC (..),
mkAccel_AES;

// ================================================================
// Bluespec library imports

import Vector       :: *;
import FIFOF        :: *;
import GetPut       :: *;
import ClientServer :: *;
import StmtFSM      :: *;

// ----------------
// BSV additional libs

import Cur_Cycle  :: *;
import GetPut_Aux :: *;
import Semi_FIFOF :: *;

// ================================================================
// Project imports

// AES Core
import AES_Params          :: *;
import AES_Defs            :: *;
import AES_IFCs            :: *;
import AES_Encrypt_Decrypt :: *;

// ================================================================
// Local defs

typedef Bit #(64)  Addr64;
typedef Bit #(64)  Data64;
typedef Bit #(128) Data128;
typedef Bool       Success;

// Symbolic names for config reg numbers
Integer regnum_cmd      = 0;
Integer regnum_status   = 1;
Integer regnum_key_addr = 2;
Integer regnum_src_addr = 3;
Integer regnum_dst_addr = 4;
Integer regnum_n_blocks = 5;
Integer n_regs          = 6;

// Symbolic names for accel commands
Integer cmd_noop       = 0;
Integer cmd_key_expand = 1;
Integer cmd_encrypt    = 2;
Integer cmd_decrypt    = 3;

// Symbolic names for status
Integer status_idle        = 0;
Integer status_busy        = 1;
Integer status_illegal_cmd = 10;
Integer status_mem_err     = 11;

// ================================================================
// Interface

interface Accel_AES_IFC;
   // ----------------
   // Slave interface (IP setup)
   //                  addr
   method Action init (Bit #(64) base_addr);

   //                 addr                success  data
   interface Server #(Bit #(64), Tuple2 #(Bool,    Bit #(64)))  slave_rd;
   //                          addr       data         success
   interface Server #(Tuple2 #(Bit #(64), Bit #(64)), Bool)     slave_wr;

   method Bool interrupt_req;

   // ----------------
   // Master interface (memory-to-memory IP operations)
   //                 addr                success  data
   interface Client #(Bit #(64), Tuple2 #(Bool,    Bit #(128)))  master_rd;
   //                          addr       data         success
   interface Client #(Tuple2 #(Bit #(64), Bit #(128)), Bool)     master_wr;
endinterface

// ================================================================
// The Accel module

function Bit #(128) fn_reverse_bytes_128b (Bit #(128) x);
   Vector #(16, Bit #(8)) v1 = unpack (x);
   Vector #(16, Bit #(8)) v2 = reverse (v1);
   return pack (v2);
endfunction

(* synthesize *)
module mkAccel_AES (Accel_AES_IFC);

   // For debugging: 0 = quiet; 1 = AES API; 2 = + AXI4 transactions
   Integer verbosity = 0;

   // Base address in the SoC address map for this IP
   Reg #(Bit #(64)) rg_base_addr <- mkRegU;
   Bit #(64) limit_addr = rg_base_addr + fromInteger (n_regs * 8);

   // Slave requests and responses
   FIFOF #(Addr64)                    f_slave_rd_reqs <- mkFIFOF;
   FIFOF #(Tuple2 #(Success, Data64)) f_slave_rd_rsps <- mkFIFOF;

   FIFOF #(Tuple2 #(Addr64, Data64))  f_slave_wr_reqs <- mkFIFOF;
   FIFOF #(Success)                   f_slave_wr_rsps <- mkFIFOF;

   // Master requests and responses
   FIFOF #(Addr64)                    f_master_rd_reqs <- mkFIFOF;
   FIFOF #(Tuple2 #(Success, Data128)) f_master_rd_rsps <- mkFIFOF;

   FIFOF #(Tuple2 #(Addr64, Data128))  f_master_wr_reqs <- mkFIFOF;
   FIFOF #(Success)                   f_master_wr_rsps <- mkFIFOF;

   // Config regs
   Reg #(Bit #(2))  rg_cmd       <- mkReg (fromInteger (cmd_noop));
   Reg #(Bit #(4))  rg_status    <- mkReg (fromInteger (status_idle));
   Reg #(Bit #(64)) rg_key_addr  <- mkRegU;
   Reg #(Bit #(64)) rg_src_addr  <- mkRegU;
   Reg #(Bit #(64)) rg_dst_addr  <- mkRegU;
   Reg #(Bit #(64)) rg_n_blocks  <- mkRegU;

   Reg #(Bool) rg_interrupt_req <- mkReg (False);

   FIFOF #(Bit #(2)) f_cmd <- mkFIFOF;

   // ================================================================
   // Configuration via Slave port

   rule rl_rd_config;
      let addr <- pop (f_slave_rd_reqs);
      let regnum  = addr [5:3];
      let success = True;
      Data64 data = 0;
      
      if (addr [2:0] != 0) begin
	 success = False;
	 $display ("%0d:%m.rl_rd_config: ERROR: misaligned addr 0x%08h", cur_cycle, addr);
      end
      else if ((addr < rg_base_addr) || (limit_addr <= addr)) begin
	 success = False;
	 $display ("%0d:%m.rl_rd_config: ERROR: unknown addr 0x%08h", cur_cycle, addr);
      end
      else if (regnum == fromInteger (regnum_cmd))       data = zeroExtend (rg_cmd);
      else if (regnum == fromInteger (regnum_status))    data = zeroExtend (rg_status);
      else if (regnum == fromInteger (regnum_key_addr))  data = rg_key_addr;
      else if (regnum == fromInteger (regnum_src_addr))  data = rg_src_addr;
      else if (regnum == fromInteger (regnum_dst_addr))  data = rg_dst_addr;
      else if (regnum == fromInteger (regnum_n_blocks))  data = rg_n_blocks;
      else begin
	 success = False;
	 $display ("%0d:%m.rl_rd_config: ERROR: unknown addr 0x%08h", cur_cycle, addr);
      end
      let result = tuple2 (success, data);
      f_slave_rd_rsps.enq (result);
      if (success && (verbosity > 0))
	 $display ("%0d: %m.rl_rd_config: addr 0x%0h => data 0x%0h", cur_cycle, addr, data);
   endrule

   rule rl_wr_config (rg_status != fromInteger (status_busy));
      match { .addr, .data } <- pop (f_slave_wr_reqs);
      let regnum  = addr [5:3];
      let success = True;

      if (addr [2:0] != 0) begin
	 success = False;
	 $display ("%0d:%m.rl_wr_config: ERROR: misaligned addr 0x%08h", cur_cycle, addr);
      end
      else if ((addr < rg_base_addr) || (limit_addr <= addr)) begin
	 success = False;
	 $display ("%0d:%m.rl_wr_config: ERROR: unknown addr 0x%08h", cur_cycle, addr);
      end
      else if (regnum == fromInteger (regnum_cmd)) begin
	 rg_cmd <= truncate (data);
	 if (data == fromInteger (cmd_noop)) begin
	    rg_status <= fromInteger (status_idle);
	 end
	 else if (   (data == fromInteger (cmd_key_expand))
		  || (data == fromInteger (cmd_encrypt))
		  || (data == fromInteger (cmd_decrypt)))
	    begin
	       rg_status <= fromInteger (status_idle);
	       f_cmd.enq (truncate (data));
	    end
	 else
	    rg_status <= fromInteger (status_illegal_cmd);
	 rg_interrupt_req <= False;
      end
      else if (regnum == fromInteger (regnum_status))    noAction;    // read-only register
      else if (regnum == fromInteger (regnum_key_addr))  rg_key_addr <= data;
      else if (regnum == fromInteger (regnum_src_addr))  rg_src_addr <= data;
      else if (regnum == fromInteger (regnum_dst_addr))  rg_dst_addr <= data;
      else if (regnum == fromInteger (regnum_n_blocks))  rg_n_blocks <= data;
      else begin
	 success = False;
	 $display ("%0d:%m.rl_wr_config: ERROR: unknown addr 0x%08h", cur_cycle, addr);
      end
      f_slave_wr_rsps.enq (success);
      if (success && (verbosity > 0))
	 $display ("%0d: %m.rl_wr_config: addr 0x%0h, data 0x%0h", cur_cycle, addr, data);
   endrule

   // ================================================================
   // Accelerator behavior
   // This is AES-specific and only interacts with the config registers (not the bus)

   // The AES core
   AES_Encrypt_Decrypt_IFC  aes_e_d <- mkAES_Encrypt_Decrypt;

   // Vars for FSM processes
   Reg #(Addr64)      rg_addr1 <- mkRegU;
   Reg #(Bit #(64))   rg_b1    <- mkRegU;

   Reg #(Bit #(128))  rg_buf2  <- mkRegU;
   Reg #(Bit #(64))   rg_b2    <- mkRegU;

   Reg #(Addr64)      rg_addr3 <- mkRegU;
   Reg #(Bit #(64))   rg_b3    <- mkRegU;

   Reg #(Bit #(64))   rg_b4    <- mkRegU;

   // This FIFO ensures sequencing between
   //      aes_e_d.encrypt/decrypt.request.put
   // and  aes_e_d.encrypt/decrypt.response.get
   // as required by this AES core.
   FIFOF #(Bit #(0)) f_tokens <- mkFIFOF;

   // ----------------
   // Key-expansion FSM
   FSM fsm_key_expand <- mkFSM (
      seq
	 par
	    // Send read request for 128b of the key
	    action
	       f_master_rd_reqs.enq (rg_key_addr);
	       if (verbosity > 1)
		  $display ("%0d: %m.fsm_key_expand: read req addr 0x%08h",
			    cur_cycle, rg_key_addr);
	    endaction
      
	    seq
	       // Receive read-response data (128b), assemble into 128b key, do key expansion.
	       action
		  match { .success, .data } <- pop (f_master_rd_rsps);
		  if (success) begin
		     // See above for "Note about byte order in memory"
		     Bit #(128) key = fn_reverse_bytes_128b (data);
		     aes_e_d.set_key (key);
		     if (verbosity > 0)
			$display ("%0d: %m.fsm_key_expand: expanding key: 0x%032h", cur_cycle, key);
		  end
		  else begin
		     rg_status <= fromInteger (status_mem_err);
		     $display ("%0d: %m.fsm_key_expand: mem response err", cur_cycle);
		  end
	       endaction
	       action
		  await (aes_e_d.key_ready);
		  rg_status <= fromInteger (status_idle);
		  rg_interrupt_req <= True;
	       endaction
	    endseq
	 endpar
      endseq);

   // ----------------
   // Encrypt/Decrypt FSM

   // FSM component
   // Generate N read requests (128b each) for words from the src buffer
   Stmt stmt_gen_rd_requests
   = seq
	rg_addr1 <= rg_src_addr;
	for (rg_b1 <= 0; rg_b1 < rg_n_blocks; rg_b1 <= rg_b1 + 1)
	   action
	      f_master_rd_reqs.enq (rg_addr1);
	      rg_addr1 <= rg_addr1 + 16;
	      if (verbosity > 1)
		 $display ("%0d: %m.fsm_gen_rd_reqs: [block %0d] addr 0x%08h",
			   cur_cycle, rg_b1, rg_addr1);
	   endaction
     endseq;

   // FSM component
   // Receive N words (128b each) as read-responses from the src buffer
   // For each word, assemble into 128b block, and request AES core to encrypt/decrypt
   Stmt stmt_process_rd_responses
   = seq
	for (rg_b2 <= 0; rg_b2 < rg_n_blocks; rg_b2 <= rg_b2 + 1) seq
	   action
	      match { .success, .data } <- pop (f_master_rd_rsps);
	      if (verbosity > 1)
		 $display ("%0d: %m.fsm_process_rd_rsps: [block %0d] success %0d data 0x%08h",
			   cur_cycle, rg_b2, success, data);
	      if (success) begin
		 // See above for "Note about byte order in memory"
		 Bit #(128) block = fn_reverse_bytes_128b (data);
		 if (rg_cmd == fromInteger (cmd_encrypt)) begin
		    aes_e_d.encrypt.request.put (block);
		    // Enable aes_e_d.encrypt.response.get, below
		    f_tokens.enq (?);
		    if (verbosity > 0)
		       $display ("%0d: %m.fsm_process_rd_rsps: encrypt [block %0d] 0x%032h",
				 cur_cycle, rg_b2, block);
		 end
		 else if (rg_cmd == fromInteger (cmd_decrypt)) begin
		    aes_e_d.decrypt.request.put (block);
		    // Enable aes_e_d.decrypt.response.get, below
		    f_tokens.enq (?);
		    if (verbosity > 0)
		       $display ("%0d: %m.fsm_process_rd_rsps: decrypt [block %0d] 0x%032h",
				 cur_cycle, rg_b2, block);
		 end
	      end
	      else if (! success)
		 rg_status <= fromInteger (status_mem_err);
	   endaction
	endseq
     endseq;

   // FSM component
   // For each of N 128b encrypted/decrypted outputs from the AES core,
   // Send write-request to the dst buffer
   Stmt stmt_gen_wr_requests
   = seq
	rg_addr3 <= rg_dst_addr;
	for (rg_b3 <= 0; rg_b3 < rg_n_blocks; rg_b3 <= rg_b3 + 1) seq
	   action
	      // Await aes_e_d.encrypt/decrypt.request.put, above
	      f_tokens.deq;
	      Bit #(128) data;
	      if (rg_cmd == fromInteger (cmd_encrypt)) begin
		 data <- aes_e_d.encrypt.response.get;
		 if (verbosity > 0)
		    $display ("%0d: %m.fsm_gen_wr_reqs: encrypted [block %0d] 0x%032h",
			   cur_cycle, rg_b3, data);
	      end
	      else begin
		 data <- aes_e_d.decrypt.response.get;
		 if (verbosity > 0)
		    $display ("%0d: %m.fsm_gen_wr_reqs: decrypted [block %0d] 0x%032h",
			   cur_cycle, rg_b3, data);
	      end
	      // See above for "Note about byte order in memory"
	      f_master_wr_reqs.enq (tuple2 (rg_addr3, fn_reverse_bytes_128b (data)));
	      rg_addr3 <= rg_addr3 + 16;
	   endaction
	endseq
     endseq;

   // FSM component
   // Receive N write-responses for writes to the dst buffer
   Stmt stmt_process_wr_responses
   = seq
	for (rg_b4 <= 0; rg_b4 < rg_n_blocks; rg_b4 <= rg_b4 + 1) action
	   let success <- pop (f_master_wr_rsps);
	   if (verbosity > 1)
	      $display ("%0d: %m.fsm_process_wr_rsps: [block %0d] success %0d",
			cur_cycle, rg_b4, success);
	   if (! success)
	      rg_status <= fromInteger (status_mem_err);
	endaction
     endseq;

   // The top-level encrypt/decrypt FSM
   // Run the above four components in parallel
   // Then signal completion
   FSM fsm_encrypt_decrypt <- mkFSM (
      seq
	 par
	    // Send read requests for input buffer
	    stmt_gen_rd_requests;

	    // Receive read-responses, assemble into 128b chunks, provide input to encryptor/decryptor
	    stmt_process_rd_responses;

	    // Get encryptor outputs, break into 32b chunks, generate write requests for output buffer
	    stmt_gen_wr_requests;

	    // Consume write-responses
	    stmt_process_wr_responses;
	 endpar

	 // Finally, signal successful completion status
	 action
	    rg_status <= fromInteger (status_idle);
	    rg_interrupt_req <= True;
	 endaction
      endseq);

   rule rl_do_command (fsm_key_expand.done
		       && fsm_encrypt_decrypt.done);
      let cmd <- pop (f_cmd);

      if (cmd == fromInteger (cmd_key_expand)) begin
	 rg_status <= fromInteger (status_busy);
	 fsm_key_expand.start;
      end

      else if (    (cmd == fromInteger (cmd_encrypt))
	       ||  (cmd == fromInteger (cmd_decrypt)))
	 begin
	    rg_status <= fromInteger (status_busy);
	    fsm_encrypt_decrypt.start;
	 end

      else begin
	 rg_status <= fromInteger (status_illegal_cmd);
	 $display ("%0d: %m.rl_do_command: unrecognized command %0d\n",
		   cur_cycle, cmd);
      end
   endrule

   // ================================================================
   // INTERFACE

   method Action init (Bit #(64) base_addr);
      rg_base_addr <= base_addr;
      rg_status    <= fromInteger (status_idle);
      rg_interrupt_req <= False;
      rg_cmd       <= fromInteger (cmd_noop);
      f_cmd.clear;

      f_slave_rd_reqs.clear;
      f_slave_rd_rsps.clear;
      f_slave_wr_reqs.clear;
      f_slave_wr_rsps.clear;

      f_master_rd_reqs.clear;
      f_master_rd_rsps.clear;
      f_master_wr_reqs.clear;
      f_master_wr_rsps.clear;
      $display ("%0d: %m.init: base_addr = 0x%0h", cur_cycle, base_addr);
   endmethod

   interface slave_rd = toGPServer (f_slave_rd_reqs, f_slave_rd_rsps);
   interface slave_wr = toGPServer (f_slave_wr_reqs, f_slave_wr_rsps);

   method Bool interrupt_req;
      return rg_interrupt_req;
   endmethod

   interface master_rd = toGPClient (f_master_rd_reqs, f_master_rd_rsps);
   interface master_wr = toGPClient (f_master_wr_reqs, f_master_wr_rsps);

endmodule: mkAccel_AES

// ================================================================

endpackage: Accel_AES
