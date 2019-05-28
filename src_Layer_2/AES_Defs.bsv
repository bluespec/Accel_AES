// Copyright (c) 2015-2017 Bluespec, Inc.  All Rights Reserved
// Author: Rishiyur S. Nikhil (Bluespec, Inc.)

// ================================================================
// This code defines common types and values for the BSV code for
// implementing AES hardware.

// Specs for this code:
//  - AES.cry in Cryptol distribution.
//         cf. "Programming Cryptol", book from Galois, Inc. (galois.com)
//         Book and Cryptol distribution containing AES.cry downloaded from:
//         http://cryptol.net
//  - AES.bsv in BSV
//         Direct transliteration of AES.cry from Cryptol to BSV
//         (no HW considaration; expands into a huge combinational ckt)

// Note: A line here beginning with '// CR nn' is a copy of line nn in
// AES.cry

// ================================================================

package AES_Defs;

// ================================================================
// imports from BSV lib

import Vector  :: *;

// ----------------------------------------------------------------
// imports for this project

import AES_Params :: *;

// ================================================================
// CR 31 // Helper type definitions
// CR 32 type GF28 = [8]
// CR 33 type State = [4][Nb]GF28

typedef  Bit #(8)                         GF28;
typedef  Vector #(4, Vector #(Nb, GF28))  State;

// CR 34 type RoundKey    = State
// CR 35 type KeySchedule = (RoundKey, [Nr-1]RoundKey, RoundKey)

typedef  State  RoundKey;
typedef  Tuple3 #(RoundKey, Vector #(TSub #(Nr, 1), RoundKey), RoundKey)  KeySchedule;

// CR 64
// CR 65 gf28MatrixMult : {n, m, k} (fin m) => ([n][m]GF28, [m][k]GF28) -> [n][k]GF28
// CR 66 gf28MatrixMult (xss, yss) = [ gf28VectorMult(xs, yss’) | xs <- xss ]
// CR 67 where yss’ = transpose yss

// In the spec, gf28MatrixMult -> gf28VectorMult -> gf28DotProduct -> gf28Add, gf28Mult
// and gf28Mult (x,y) = truncate (pmod (pmult (x, y),  irreducible));
// and pmult and pmod are complicated functions.
// Instead, we implement gf28MatrixMult in a specialized way, exploiting:
// - in the call from mixColumns, all elements of the left matrix are
//     1, 2 or 3
// - in the call from invMixColumns, all elements of the left matrix
//     are 9, b, d or e
// Instead of passing a left-matrix with these constants,
// we pass a left-matrix with curried functions (mult by constant)
//     mult_1, mult_2, mult_3, mult_9, mult_b, mult_d and mult_e

typedef function GF28 f (GF28 x)  Func_GF28_to_GF28;
typedef Vector #(4, Vector #(4, Func_GF28_to_GF28)) FuncMat;

function State gf28MatrixMult (FuncMat m, State n);
   State x = replicate (replicate (0));

   for( Integer i = 0; i < 4; i = i+1) begin
      for( Integer j = 0; j < 4; j = j+1) begin
	 for( Integer k = 0; k < 4; k = k+1 ) begin
            x[i][j] = x[i][j] ^ m[i][k] (n[k][j]);
	 end
      end
   end

   return x;
endfunction

function Bit #(8) mult_1 (Bit #(8) a);
   return a;
endfunction

function Bit #(8) mult_2 (Bit #(8) a);
   return ((a & 'h80)!=0) ? ((a<<1) ^ 8'h1B) : (a<<1);
endfunction

function Bit #(8) mult_3 (Bit #(8) a);
   return mult_2 (a) ^ a;
endfunction

function Bit #(8) mult_9 (Bit #(8) a);
   let a2 = mult_2 (a);
   let a4 = mult_2 (a2);
   let a8 = mult_2 (a4);
   return (a8 ^ a);
endfunction

function Bit #(8) mult_b (Bit #(8) a);
   let a2 = mult_2 (a);
   let a4 = mult_2 (a2);
   let a8 = mult_2 (a4);
   return (a8 ^ a2 ^ a);
endfunction

function Bit #(8) mult_d (Bit#(8) a);
   let a2 = mult_2 (a);
   let a4 = mult_2 (a2);
   let a8 = mult_2 (a4);
   return (a8 ^ a4 ^ a);
endfunction

function Bit #(8) mult_e (Bit #(8) a);
   let a2 = mult_2 (a);
   let a4 = mult_2 (a2);
   let a8 = mult_2 (a4);
   return (a8 ^ a4 ^ a2);
endfunction

// CR 76 // The SubBytes transform and its inverse
// CR 77 SubByte : GF28 -> GF28
// CR 78 SubByte b = xformByte (gf28Inverse b)

// CR 79
// CR 80 SubByte’ : GF28 -> GF28
// CR 81 SubByte’ b = sbox@b

function GF28 subByte_prime (GF28 b) = sbox [b];

// CR 82
// CR 83 SubBytes : State -> State
// CR 84 SubBytes state = [ [ SubByte’ b | b <- row ] | row <- state ]

function State subBytes (State state) = map (map (subByte_prime), state);

// CR 85
// CR 86
// CR 87 InvSubByte : GF28 -> GF28
// CR 88 InvSubByte b = gf28Inverse (xformByte’ b)

function GF28 invSubByte_prime (GF28 b) = inv_sbox [b];

// CR 89
// CR 90 InvSubBytes : State -> State
// CR 91 InvSubBytes state =[ [ InvSubByte b | b <- row ] | row <- state ]

function State invSubBytes (State state) = map (map (invSubByte_prime), state);

// CR 92
// CR 93 // The ShiftRows transform and its inverse
// CR 94 ShiftRows : State -> State
// CR 95 ShiftRows state = [ row <<< shiftAmount | row <- state
// CR 96                                         | shiftAmount <- [0 .. 3]
// CR 97                   ]

function State shiftRows (State state);
   function Vector #(Nb, GF28) shiftRow (Integer j) = rotateBy (state [j], fromInteger ((nb - j) % nb));
   return genWith (shiftRow);
endfunction

// CR 98
// CR 99 InvShiftRows : State -> State
// CR 100 InvShiftRows state = [ row >>> shiftAmount | row <- state
// CR 101                                            | shiftAmount <- [0 .. 3]
// CR 102                      ]

function State invShiftRows (State state);
   function Vector #(Nb, GF28) shiftRow (Integer j) = rotateBy (state [j], fromInteger (j));
   return genWith (shiftRow);
endfunction

// CR 103
// CR 104 // The MixColumns transform and its inverse
// CR 105 MixColumns : State -> State
// CR 106 MixColumns state = gf28MatrixMult (m, state)
// CR 107 where m = [[2, 3, 1, 1],
// CR 108 [1, 2, 3, 1],
// CR 109 [1, 1, 2, 3],
// CR 110 [3, 1, 1, 2]]

function State mixColumns (State state);
   Func_GF28_to_GF28 x0 [4] = {mult_2, mult_3, mult_1, mult_1};
   Func_GF28_to_GF28 x1 [4] = {mult_1, mult_2, mult_3, mult_1};
   Func_GF28_to_GF28 x2 [4] = {mult_1, mult_1, mult_2, mult_3};
   Func_GF28_to_GF28 x3 [4] = {mult_3, mult_1, mult_1, mult_2};
   Array #(Func_GF28_to_GF28) xys [4] = { x0, x1, x2, x3 };
   FuncMat m = map (arrayToVector, arrayToVector (xys));
   return gf28MatrixMult (m, state);
endfunction

// CR 111
// CR 112 InvMixColumns : State -> State
// CR 113 InvMixColumns state = gf28MatrixMult (m, state)
// CR 114 where m = [[0x0e, 0x0b, 0x0d, 0x09],
// CR 115 [0x09, 0x0e, 0x0b, 0x0d],
// CR 116 [0x0d, 0x09, 0x0e, 0x0b],
// CR 117 [0x0b, 0x0d, 0x09, 0x0e]]

function State invMixColumns (State state);
   Func_GF28_to_GF28 x0 [4] = {mult_e, mult_b, mult_d, mult_9};
   Func_GF28_to_GF28 x1 [4] = {mult_9, mult_e, mult_b, mult_d};
   Func_GF28_to_GF28 x2 [4] = {mult_d, mult_9, mult_e, mult_b};
   Func_GF28_to_GF28 x3 [4] = {mult_b, mult_d, mult_9, mult_e};
   Array #(Func_GF28_to_GF28) xys [4] = { x0, x1, x2, x3 };
   FuncMat m = map (arrayToVector, arrayToVector (xys));
   return gf28MatrixMult (m, state);
endfunction

// CR 118
// CR 119 // The AddRoundKey transform
// CR 120 AddRoundKey : (RoundKey, State) -> State
// CR 121 AddRoundKey (rk, s) = rk ^ s

function State addRoundKey (RoundKey rk, State s) = zipWith (zipWith (\^  ), rk, s);

// CR 122 // Key expansion
// CR 123 Rcon : [8] -> [4]GF28
// CR 124 Rcon i = [(gf28Pow (<| x |>, i-1)), 0, 0, 0]

// rcon is only called with args 1..10
// rcon_table 'memoizes' the function for args 0..10
// (These values are generated in Cryptol or in BSV AES_Spec)

Vector #(11, GF28) rcon_table
   = begin
	GF28 arr [11] = {   ?, 'h01, 'h02, 'h04,
			 'h08, 'h10, 'h20, 'h40,
			 'h80, 'h1b, 'h36 };
	arrayToVector (arr);
     end;

function Vector #(4, GF28) rcon_prime (Bit #(4) i);
   GF28 xs [4] = {rcon_table [i], 0, 0, 0};
   return arrayToVector (xs);
endfunction

// CR 125
// CR 126 SubWord : [4]GF28 -> [4]GF28
// CR 127 SubWord bs = [ SubByte' b | b <- bs ]

function Vector #(4, GF28) subWord (Vector #(4, GF28) bs) = map (subByte_prime, bs);

// CR 128
// CR 129 RotWord : [4]GF28 -> [4]GF28
// CR 130 RotWord [a0, a1, a2, a3] = [a1, a2, a3, a0]

function Vector #(4, GF28) rotWord (Vector #(4, GF28) as);
   GF28 x [4] = {as[1], as[2], as[3], as[0]};
   return arrayToVector (x);
endfunction

// CR 131
// CR 132 NextWord : ([8],[4][8],[4][8]) -> [4][8]
// CR 133 NextWord(i, prev, old) = old ^ mask
// CR 134    where mask = if i % ‘Nk == 0
// CR 135                 then SubWord(RotWord(prev)) ^ Rcon (i / ‘Nk)
// CR 136                 else if (‘Nk > 6) && (i % ‘Nk == 4)
// CR 137                      then SubWord(prev)
// CR 138                      else prev

function Vector #(4, Bit #(8)) nextWord (Bit #(6)               i,
					 Vector #(4, Bit #(8))  prev,
					 Vector #(4, Bit #(8))  old);
   let mask = (  ((i % fromInteger (nk)) == 0)
	       ? zipWith (\^  , subWord (rotWord (prev)), rcon_prime (truncate (i / fromInteger (nk))))
	       : (  (nk > 6) && ((i % fromInteger (nk)) == 4)
		  ? subWord (prev)
		  : prev ));
   return zipWith (\^  , old, mask);
endfunction

// CR 164
// CR 165 // AES rounds and inverses
// CR 166 AESRound : (RoundKey, State) -> State
// CR 167 AESRound (rk, s) = AddRoundKey (rk, MixColumns (ShiftRows (SubBytes s)))

function State aesRound (RoundKey rk, State s) = addRoundKey (rk, mixColumns (shiftRows (subBytes (s))));

// CR 168
// CR 169 AESFinalRound : (RoundKey, State) -> State
// CR 170 AESFinalRound (rk, s) = AddRoundKey (rk, ShiftRows (SubBytes s))

function State aesFinalRound (RoundKey rk, State s) = addRoundKey (rk, shiftRows (subBytes (s)));

// CR 171
// CR 172 AESInvRound : (RoundKey, State) -> State
// CR 173 AESInvRound (rk, s) =
// CR 174       InvMixColumns (AddRoundKey (rk, InvSubBytes (InvShiftRows s)))

function State aesInvRound (RoundKey rk, State s) =
   invMixColumns (addRoundKey (rk, invSubBytes (invShiftRows (s))));

// CR 175 AESFinalInvRound : (RoundKey, State) -> State
// CR 176 AESFinalInvRound (rk, s) = AddRoundKey (rk, InvSubBytes (InvShiftRows s))

function State aesFinalInvRound (RoundKey rk, State s) = addRoundKey (rk, invSubBytes (invShiftRows (s)));

// CR 177
// CR 178 // Converting a 128 bit message to a State and back
// CR 179 msgToState : [128] -> State
// CR 180 msgToState msg = transpose (split (split msg))

function State msgToState (Bit #(128) msg);
   Vector #(16, GF28) x = unpack (msg);
   Vector #(16, GF28) y = reverse (x);
   State              z = unpack (pack (y));
   return transpose (z);
endfunction

// CR 181
// CR 182 stateToMsg : State -> [128]
// CR 183 stateToMsg st = join (join (transpose st))

function Bit #(128) stateToMsg (State st);
   State              x = transpose (st);
   Vector #(16, GF28) y = unpack (pack (x));
   Vector #(16, GF28) z = reverse (y);
   return pack (z);
endfunction

// CR 203
// CR 204 sbox : [256]GF28
// CR 205 sbox = [
// CR 206 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
// CR 207 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
// CR 208 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
// CR 209 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
// CR 210 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
// CR 211 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
// CR 212 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
// CR 213 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
// CR 214 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
// CR 215 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
// CR 216 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
// CR 217 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
// CR 218 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
// CR 219 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
// CR 220 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
// CR 221 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
// CR 222 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
// CR 223 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
// CR 224 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
// CR 225 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
// CR 226 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
// CR 227 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
// CR 228 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
// CR 229 0x54, 0xbb, 0x16]

GF28 sbox [256] = {
        'h63, 'h7c, 'h77, 'h7b, 'hf2, 'h6b, 'h6f, 'hc5, 'h30, 'h01, 'h67,
	'h2b, 'hfe, 'hd7, 'hab, 'h76, 'hca, 'h82, 'hc9, 'h7d, 'hfa, 'h59,
	'h47, 'hf0, 'had, 'hd4, 'ha2, 'haf, 'h9c, 'ha4, 'h72, 'hc0, 'hb7,
        'hfd, 'h93, 'h26, 'h36, 'h3f, 'hf7, 'hcc, 'h34, 'ha5, 'he5, 'hf1,
        'h71, 'hd8, 'h31, 'h15, 'h04, 'hc7, 'h23, 'hc3, 'h18, 'h96, 'h05,
        'h9a, 'h07, 'h12, 'h80, 'he2, 'heb, 'h27, 'hb2, 'h75, 'h09, 'h83,
        'h2c, 'h1a, 'h1b, 'h6e, 'h5a, 'ha0, 'h52, 'h3b, 'hd6, 'hb3, 'h29,
        'he3, 'h2f, 'h84, 'h53, 'hd1, 'h00, 'hed, 'h20, 'hfc, 'hb1, 'h5b,
        'h6a, 'hcb, 'hbe, 'h39, 'h4a, 'h4c, 'h58, 'hcf, 'hd0, 'hef, 'haa,
        'hfb, 'h43, 'h4d, 'h33, 'h85, 'h45, 'hf9, 'h02, 'h7f, 'h50, 'h3c,
        'h9f, 'ha8, 'h51, 'ha3, 'h40, 'h8f, 'h92, 'h9d, 'h38, 'hf5, 'hbc,
        'hb6, 'hda, 'h21, 'h10, 'hff, 'hf3, 'hd2, 'hcd, 'h0c, 'h13, 'hec,
        'h5f, 'h97, 'h44, 'h17, 'hc4, 'ha7, 'h7e, 'h3d, 'h64, 'h5d, 'h19,
        'h73, 'h60, 'h81, 'h4f, 'hdc, 'h22, 'h2a, 'h90, 'h88, 'h46, 'hee,
        'hb8, 'h14, 'hde, 'h5e, 'h0b, 'hdb, 'he0, 'h32, 'h3a, 'h0a, 'h49,
        'h06, 'h24, 'h5c, 'hc2, 'hd3, 'hac, 'h62, 'h91, 'h95, 'he4, 'h79,
        'he7, 'hc8, 'h37, 'h6d, 'h8d, 'hd5, 'h4e, 'ha9, 'h6c, 'h56, 'hf4,
        'hea, 'h65, 'h7a, 'hae, 'h08, 'hba, 'h78, 'h25, 'h2e, 'h1c, 'ha6,
        'hb4, 'hc6, 'he8, 'hdd, 'h74, 'h1f, 'h4b, 'hbd, 'h8b, 'h8a, 'h70,
        'h3e, 'hb5, 'h66, 'h48, 'h03, 'hf6, 'h0e, 'h61, 'h35, 'h57, 'hb9,
        'h86, 'hc1, 'h1d, 'h9e, 'he1, 'hf8, 'h98, 'h11, 'h69, 'hd9, 'h8e,
        'h94, 'h9b, 'h1e, 'h87, 'he9, 'hce, 'h55, 'h28, 'hdf, 'h8c, 'ha1,
        'h89, 'h0d, 'hbf, 'he6, 'h42, 'h68, 'h41, 'h99, 'h2d, 'h0f, 'hb0,
	'h54, 'hbb, 'h16 };

// inv_sbox is a lookup table for invSubByte ()

GF28 inv_sbox [256] = {
        'h52, 'h09, 'h6a, 'hd5, 'h30, 'h36, 'ha5, 'h38, 'hbf, 'h40, 'ha3,
        'h9e, 'h81, 'hf3, 'hd7, 'hfb, 'h7c, 'he3, 'h39, 'h82, 'h9b, 'h2f,
        'hff, 'h87, 'h34, 'h8e, 'h43, 'h44, 'hc4, 'hde, 'he9, 'hcb, 'h54,
        'h7b, 'h94, 'h32, 'ha6, 'hc2, 'h23, 'h3d, 'hee, 'h4c, 'h95, 'h0b,
        'h42, 'hfa, 'hc3, 'h4e, 'h08, 'h2e, 'ha1, 'h66, 'h28, 'hd9, 'h24,
        'hb2, 'h76, 'h5b, 'ha2, 'h49, 'h6d, 'h8b, 'hd1, 'h25, 'h72, 'hf8,
        'hf6, 'h64, 'h86, 'h68, 'h98, 'h16, 'hd4, 'ha4, 'h5c, 'hcc, 'h5d,
        'h65, 'hb6, 'h92, 'h6c, 'h70, 'h48, 'h50, 'hfd, 'hed, 'hb9, 'hda,
        'h5e, 'h15, 'h46, 'h57, 'ha7, 'h8d, 'h9d, 'h84, 'h90, 'hd8, 'hab,
        'h00, 'h8c, 'hbc, 'hd3, 'h0a, 'hf7, 'he4, 'h58, 'h05, 'hb8, 'hb3,
        'h45, 'h06, 'hd0, 'h2c, 'h1e, 'h8f, 'hca, 'h3f, 'h0f, 'h02, 'hc1,
        'haf, 'hbd, 'h03, 'h01, 'h13, 'h8a, 'h6b, 'h3a, 'h91, 'h11, 'h41,
        'h4f, 'h67, 'hdc, 'hea, 'h97, 'hf2, 'hcf, 'hce, 'hf0, 'hb4, 'he6,
        'h73, 'h96, 'hac, 'h74, 'h22, 'he7, 'had, 'h35, 'h85, 'he2, 'hf9,
        'h37, 'he8, 'h1c, 'h75, 'hdf, 'h6e, 'h47, 'hf1, 'h1a, 'h71, 'h1d,
        'h29, 'hc5, 'h89, 'h6f, 'hb7, 'h62, 'h0e, 'haa, 'h18, 'hbe, 'h1b,
        'hfc, 'h56, 'h3e, 'h4b, 'hc6, 'hd2, 'h79, 'h20, 'h9a, 'hdb, 'hc0,
        'hfe, 'h78, 'hcd, 'h5a, 'hf4, 'h1f, 'hdd, 'ha8, 'h33, 'h88, 'h07,
        'hc7, 'h31, 'hb1, 'h12, 'h10, 'h59, 'h27, 'h80, 'hec, 'h5f, 'h60,
        'h51, 'h7f, 'ha9, 'h19, 'hb5, 'h4a, 'h0d, 'h2d, 'he5, 'h7a, 'h9f,
        'h93, 'hc9, 'h9c, 'hef, 'ha0, 'he0, 'h3b, 'h4d, 'hae, 'h2a, 'hf5,
        'hb0, 'hc8, 'heb, 'hbb, 'h3c, 'h83, 'h53, 'h99, 'h61, 'h17, 'h2b,
        'h04, 'h7e, 'hba, 'h77, 'hd6, 'h26, 'he1, 'h69, 'h14, 'h63, 'h55,
        'h21, 'h0c, 'h7d };

// ================================================================
// Other help functions

// Display an AES round 'state'

function Action display_state (State state);
   action
      $display ("   [", fshow (state [0]), "  ", fshow (state [1]));
      $display ("    ", fshow (state [2]), "  ", fshow (state [3]), "]");
   endaction
endfunction

// ================================================================

endpackage
