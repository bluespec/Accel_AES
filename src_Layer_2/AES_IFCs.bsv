// Copyright (c) 2015-2017 Bluespec, Inc.  All Rights Reserved
// Author: Rishiyur S. Nikhil (Bluespec, Inc.)

// ================================================================
// Standard interfaces to HW AES encryption and decryption modules.

// Typical use model for each interface:
//   - Supply a key on the 'set_key' interface.
//   - Use the Server interface one or more times to encrypt/decrypt
//       one or more blocks of text.

// There can be many modules implementing these interfaces, varying in
// simplicity/complexity, hardware resources (gates, RAMS, ...),
// circuit speed (MHz), latency, throughput, power and energy
// consumption, etc.

// The AES_Encrypt_IFC and AES_Decrypt interfaces are for
// implementations that can run encryption and decryption
// concurrently.

// The AES_Encrypt_Decrypt_IFC interface is for implementations where
// encryption and decryption share the 'set_key' and 'key_ready' logic
// since key-expansion is identical for both.

// ================================================================

package AES_IFCs;

// ================================================================
// imports from BSV lib

import Vector        :: *;
import GetPut        :: *;
import ClientServer  :: *;

// ----------------------------------------------------------------
// imports for this project

import AES_Params :: *;

// ================================================================
// Encryption box interface

interface AES_Encrypt_IFC;
   // Supply the key here.
   // This will kick off an internal process to expand the key into
   // the full key schedule.
   method Action set_key (Bit #(AESKeySize) key);

   // Indicator that key expansion is complete.
   // This is provided as a convenience, if needed (the 'request'
   // sub-interface in the Server below will not accept inputs until
   // key-expansion is complete).
   method Bool key_ready;

   // put plaintext and get ciphertext here
   interface Server #(Bit #(128), Bit #(128)) encrypt;
endinterface

// ================================================================
// Decryption box interface

interface AES_Decrypt_IFC;
   // Supply the key here.
   // This will kick off an internal process to expand the key into
   // the full key schedule.
   method Action set_key (Bit #(AESKeySize) key);

   // Indicator that key expansion is complete.
   // This is provided as a convenience, if needed (the 'request'
   // sub-interface in the Server below will not accept inputs until
   // key-expansion is complete).
   method Bool key_ready;

   // put ciphertext and get plaintext here
   interface Server #(Bit #(128), Bit #(128)) decrypt;
endinterface

// ================================================================
// Encryption-and-decryption box interface

interface AES_Encrypt_Decrypt_IFC;
   // Supply the key here.
   // This will kick off an internal process to expand the key into
   // the full key schedule.
   method Action set_key (Bit #(AESKeySize) key);

   // Indicator that key expansion is complete.
   // This is provided as a convenience, if needed (the 'request'
   // sub-interface in the Server below will not accept inputs until
   // key-expansion is complete).
   method Bool key_ready;

   // Encryption: put plaintext and get ciphertext here
   interface Server #(Bit #(128), Bit #(128)) encrypt;

   // Decryption: put ciphertext and get plaintext here
   interface Server #(Bit #(128), Bit #(128)) decrypt;
endinterface

// ================================================================

endpackage
