// Copyright (c) 2015-2017 Bluespec, Inc.  All Rights Reserved
// Author: Rishiyur S. Nikhil (Bluespec, Inc.)

// ================================================================
// This code implements a "Key Expand" module for the AES algorithm.

// Spec for this code: AES.cry in Cryptol distribution.
// cf. "Programming Cryptol", book from Galois, Inc. (galois.com)
// Book and Cryptol distribution containing AES.cry downloaded from:
//     http://cryptol.net

// ================================================================

package AES_KeyExpand;

// ================================================================
// imports from BSV lib

import Vector  :: *;
import StmtFSM :: *;

// ----------------------------------------------------------------
// imports for this project

import AES_Params  :: *;
import AES_Defs    :: *;

// ================================================================
// INTERFACE

interface AES_KeyExpand_IFC;
   // Deposit the key here.
   // This will kick off an internal process to expand the key into
   // the full key schedule.

   method Action set_key (Bit #(AESKeySize) key);

   // Indicator that key expansion is complete
   // (apps may not need this; method keySchedule is not enabled while key expansion is in progress)
   method Bool key_ready;

   // The key schedule
   method KeySchedule keySchedule;
endinterface

// ================================================================
// MODULE

module mkAES_KeyExpand (AES_KeyExpand_IFC);

   // keyWS state
   Vector #(TMul #(TAdd #(Nr, 1), Nb),
	    Reg #(Vector #(4, Bit #(8))))  keyWS_state <- replicateM (mkRegU);

   Reg #(Bit #(6)) rg_i <- mkRegU;

   // ----------------------------------------------------------------

   function KeySchedule fn_keySchedule;
      Vector #(TAdd #(Nr, 1), Vector #(Nb, Vector #(4, Bit #(8)))) g = unpack (pack (readVReg (keyWS_state)));
      Vector #(TAdd #(Nr, 1), Vector #(4, Vector #(Nb, Bit #(8)))) keys = map (transpose, g);
      KeySchedule keySched = tuple3 (keys [0], tail (init (keys)), keys [nr]);
      return keySched;
   endfunction

   // ----------------------------------------------------------------
   // BEHAVIOR

   FSM fsm_expandKey <- mkFSM (
      seq
	 // keyWS ()
         for (rg_i <= fromInteger (nk); rg_i < fromInteger ((nr+1) * nb) ; rg_i <= rg_i + 1) action
	    let prev = keyWS_state [rg_i-1];
	    let old = keyWS_state [rg_i-fromInteger (nk)];
	    keyWS_state [rg_i] <= nextWord (rg_i, prev, old);
	 endaction
      endseq
      );

   // ----------------------------------------------------------------
   // INTERFACE

   // Deposit the key here.
   // This will kick off an internal process to expand the key into
   // the full key schedule.

   method Action set_key (Bit #(AESKeySize) key) if (fsm_expandKey.done);
      // Initialize key expansion (cf. first part of expandKey())
      Vector #(Nk, Vector #(4, Bit #(8))) seed = map (reverse, reverse (unpack (key)));
      for (Integer i = 0; i < nk; i = i + 1)
	 keyWS_state [i] <= seed [i];

      // Start the key-expansion fsm
      fsm_expandKey.start;
   endmethod

   // Indicator that key expansion is complete
   // (apps may not need this; method keySchedule is not enabled while key expansion is in progress)
   method Bool key_ready;
      return fsm_expandKey.done;
   endmethod

   // The key schedule
   method KeySchedule keySchedule;
      return fn_keySchedule;
   endmethod

endmodule

// ================================================================

endpackage
