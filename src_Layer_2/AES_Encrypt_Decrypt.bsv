// Copyright (c) 2015-2017 Bluespec, Inc.  All Rights Reserved
// Author: Rishiyur S. Nikhil (Bluespec, Inc.)

// ================================================================
// This code implements the core functions of the AES algorithm:
//     key expansion of a 128b key
//     encryption of a 128b block using that key
//     decryption of a 128b block using that key
// The AES 'rounds' are done sequentially, with each round
// transforming a single 'state' register.

// Spec for this code: AES.cry in Cryptol distribution.
// cf. "Programming Cryptol", book from Galois, Inc. (galois.com)
// Book and Cryptol distribution containing AES.cry downloaded from:
//     http://cryptol.net

// ================================================================

package AES_Encrypt_Decrypt;

// ================================================================
// imports from BSV lib

import Vector        :: *;
import StmtFSM       :: *;
import GetPut        :: *;
import ClientServer  :: *;

// ----------------------------------------------------------------
// imports for this project

import AES_Params     :: *;
import AES_Defs       :: *;
import AES_KeyExpand  :: *;
import AES_IFCs       :: *;

// ================================================================
// The encryption module

(* synthesize *)
module mkAES_Encrypt_Decrypt (AES_Encrypt_Decrypt_IFC);

   // Key-expansion sub-module

   AES_KeyExpand_IFC keyExpand <- mkAES_KeyExpand;

   match { .ekInit,  .eks, .ekFinal } = keyExpand.keySchedule;
   match { .dkFinal, .dks, .dkInit  } = keyExpand.keySchedule;

   // AES Round state

   Reg #(State) rg_state <- mkRegU;

   // ----------------------------------------------------------------
   // BEHAVIOR

   Reg #(Bit #(4)) rg_j <- mkRegU;

   FSM fsm_aesEncrypt <- mkFSM (
      seq
	 rg_state <= addRoundKey (ekInit, rg_state);
	 for (rg_j <= 1; rg_j < fromInteger (nr); rg_j <= rg_j + 1) action
            rg_state <= aesRound (eks [rg_j - 1], rg_state);
	 endaction
	 rg_state <= aesFinalRound (ekFinal, rg_state);
      endseq
      );

   FSM fsm_aesDecrypt <- mkFSM (
      seq
	 rg_state <= addRoundKey (dkInit, rg_state);
	 for (rg_j <= 1; rg_j < fromInteger (nr); rg_j <= rg_j + 1) action
	    rg_state <= aesInvRound (reverse (dks) [rg_j - 1], rg_state);
	 endaction
	 rg_state <= aesFinalInvRound (dkFinal, rg_state);
      endseq
      );

   // ----------------------------------------------------------------
   // INTERFACE

   // Supply the key here.
   // This will kick off an internal process to expand the key into
   // the full key schedule.
   method Action set_key (Bit #(AESKeySize) key);
      keyExpand.set_key (key);
   endmethod

   // Indicator that key expansion is complete.
   // This is provided as a convenience, if needed (the 'request'
   // sub-interface in the Server below will not accept inputs until
   // key-expansion is complete).
   method Bool key_ready;
      return keyExpand.key_ready;
   endmethod

   // Encryption: put plaintext and get ciphertext here
   interface Server encrypt;
      interface Put request;
	 method Action put (Bit #(128) plaintext) if (keyExpand.key_ready);
	    rg_state <= msgToState (plaintext);
	    fsm_aesEncrypt.start;
	 endmethod
      endinterface
      interface Get response;
	 method ActionValue #(Bit #(128)) get () if (keyExpand.key_ready && fsm_aesEncrypt.done);
	    let ciphertext = stateToMsg (rg_state);
	    return ciphertext;
	 endmethod
      endinterface
   endinterface

   // Decryption: put ciphertext and get plaintext here
   interface Server decrypt;
      interface Put request;
	 method Action put (Bit #(128) ciphertext) if (keyExpand.key_ready);
	    rg_state <= msgToState (ciphertext);
	    fsm_aesDecrypt.start;
	 endmethod
      endinterface
      interface Get response;
	 method ActionValue #(Bit #(128)) get () if (keyExpand.key_ready && fsm_aesDecrypt.done);
	    let plaintext = stateToMsg (rg_state);
	    return plaintext;
	 endmethod
      endinterface
   endinterface

endmodule

// ================================================================

endpackage
