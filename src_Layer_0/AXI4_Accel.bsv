// Copyright (c) 2019 Bluespec, Inc. All Rights Reserved.
// Author: Rishiyur S. Nikhil

package AXI4_Accel;

// ================================================================
// This is a wrapper for Accel_AES, an AES accelerator with generic
// bus interfaces, adapting it in particular for AXI4.

// ================================================================
// Bluespec library imports

import FIFOF        :: *;
import GetPut       :: *;
import ClientServer :: *;

// ----------------
// BSV additional libs

import Cur_Cycle  :: *;
import GetPut_Aux :: *;
import Semi_FIFOF :: *;

// ================================================================
// Project imports

import AXI4_Types     :: *;
import Fabric_Defs    :: *;
import AXI4_Accel_IFC :: *;
import Accel_AES      :: *;

// ================================================================
// Implementation

(* synthesize*)
module mkAXI4_Accel (AXI4_Accel_IFC);
   // 0 = quiet; 1 = show AXI4 traffic
   Integer verbosity = 0;

   Reg #(Bit #(Wd_Id))    rg_axi4_id   <- mkReg (0);

   Accel_AES_IFC accel <- mkAccel_AES;

   AXI4_Slave_Xactor_IFC #(Wd_Id,
			   Wd_Addr,
			   Wd_Data,
			   Wd_User) slave_xactor <- mkAXI4_Slave_Xactor;

   AXI4_Master_Xactor_IFC #(Wd_Id,
			    Wd_Addr,
			    Wd_Data,
			    Wd_User) master_xactor <- mkAXI4_Master_Xactor;

   // For slave reads
   FIFOF #(AXI4_Rd_Addr #(Wd_Id, Wd_Addr, Wd_User)) f_slave_rd_addr <- mkFIFOF;

   // For slave writes
   FIFOF #(AXI4_Wr_Addr #(Wd_Id, Wd_Addr, Wd_User)) f_slave_wr_addr <- mkFIFOF;

   // For master reads
   FIFOF #(AXI4_Rd_Addr #(Wd_Id, Wd_Addr, Wd_User)) f_master_rd_addr <- mkFIFOF;

   // For master writes
   FIFOF #(AXI4_Wr_Addr #(Wd_Id, Wd_Addr, Wd_User)) f_master_wr_addr <- mkFIFOF;

   // For master reads
   Reg #(Bool)      master_rd_rsp_beat0      <- mkReg (True);
   Reg #(Bool)      master_rd_rsp_success0 <- mkRegU;
   Reg #(Bit #(64)) master_rd_rsp_data0    <- mkRegU;

   // For master writes
   Reg #(Bool)      rg_master_wr_req_beat0   <- mkReg (True);
   Reg #(Bit #(64)) rg_master_wr_req_data1 <- mkRegU;

   // ================================================================
   // Slave reads

   rule rl_slave_rd_reqs;
      let rd_addr <- pop_o (slave_xactor.o_rd_addr);
      accel.slave_rd.request.put (rd_addr.araddr);
      f_slave_rd_addr.enq (rd_addr);

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_slave_rd_reqs:", cur_cycle);
	 $display ("    ", fshow (rd_addr));
      end
   endrule

   rule rl_slave_rd_rsps;
      let rd_addr <- pop (f_slave_rd_addr);
      match { .success, .data } <- accel.slave_rd.response.get;

      AXI4_Rd_Data #(Wd_Id, Wd_Data, Wd_User)
      rd_data = AXI4_Rd_Data {rid:   rd_addr.arid,
			      rdata: data,
			      rresp: (success ? axi4_resp_okay : axi4_resp_slverr),
			      rlast: True,
			      ruser: rd_addr.aruser};

      slave_xactor.i_rd_data.enq (rd_data);

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_slave_rd_rsps:", cur_cycle);
	 $display ("    ", fshow (rd_addr));
	 $display ("    ", fshow (rd_data));
      end
   endrule

   // ================================================================
   // Slave writes

   rule rl_slave_wr_req;
      let wr_addr <- pop_o (slave_xactor.o_wr_addr);
      let wr_data <- pop_o (slave_xactor.o_wr_data);
      accel.slave_wr.request.put (tuple2 (wr_addr.awaddr, wr_data.wdata));
      f_slave_wr_addr.enq (wr_addr);

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_slave_wr_req:", cur_cycle);
	 $display ("    ", fshow (wr_addr));
	 $display ("    ", fshow (wr_data));
      end
   endrule

   rule rl_slave_wr_rsp;
      let wr_addr <- pop (f_slave_wr_addr);
      let success <- accel.slave_wr.response.get;

      AXI4_Wr_Resp #(Wd_Id, Wd_User)
      wr_resp = AXI4_Wr_Resp {bid:   wr_addr.awid,
			      bresp: (success ? axi4_resp_okay : axi4_resp_slverr),
			      buser: wr_addr.awuser};
      slave_xactor.i_wr_resp.enq (wr_resp);

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_slave_wr_rsp:", cur_cycle);
	 $display ("    ", fshow (wr_addr));
	 $display ("    ", fshow (wr_resp));
      end
   endrule

   // ================================================================
   // Master reads
   // Each 128b transaction with the accel becomes a 2-beat burst (64b/beat) on the AXI4 bus

   rule rl_master_rd_req;
      let addr <- accel.master_rd.request.get;

      AXI4_Rd_Addr #(Wd_Id, Wd_Addr, Wd_User)
      rd_addr = AXI4_Rd_Addr {arid:     rg_axi4_id,
			      araddr:   addr,
			      arlen:    1,               // 2-beat burst
			      arsize:   axsize_8,
			      arburst:  axburst_incr,    // incrementing burst
			      arlock:   axlock_normal,
			      arcache:  arcache_dev_nonbuf,
			      arprot:   { axprot_2_data, axprot_1_non_secure, axprot_0_unpriv },
			      arqos:    0,
			      arregion: 0,
			      aruser:   0};
      master_xactor.i_rd_addr.enq (rd_addr);

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_master_rd_req:", cur_cycle);
	 $display ("    ", fshow (rd_addr));
      end
   endrule

   rule rl_master_rd_rsps_beat0 (master_rd_rsp_beat0);
      let rd_data <- pop_o (master_xactor.o_rd_data);
      master_rd_rsp_success0 <= (rd_data.rresp == axi4_resp_okay);
      master_rd_rsp_data0    <= rd_data.rdata;
      master_rd_rsp_beat0    <= False;

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_master_rd_rsps_beat0:", cur_cycle);
	 $display ("    ", fshow (rd_data));
      end
   endrule

   rule rl_master_rd_rsps_beat1 (! master_rd_rsp_beat0);
      let rd_data <- pop_o (master_xactor.o_rd_data);
      Bool       success = master_rd_rsp_success0 && (rd_data.rresp == axi4_resp_okay);
      Bit #(128) data    = { rd_data.rdata, master_rd_rsp_data0 };
      accel.master_rd.response.put (tuple2 (success, data));
      master_rd_rsp_beat0 <= True;

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_master_rd_rsps_beat1:", cur_cycle);
	 $display ("    ", fshow (rd_data));
      end
   endrule

   // ================================================================
   // Master writes
   // Each 128b transaction with the accel becomes a 2-beat burst (64b/beat) on the AXI4 bus

   rule rl_master_wr_reqs_beat0 (rg_master_wr_req_beat0);
      match { .addr, .data } <- accel.master_wr.request.get;

      AXI4_Wr_Addr #(Wd_Id, Wd_Addr, Wd_User)
      wr_addr = AXI4_Wr_Addr {awid:     rg_axi4_id,
			      awaddr:   addr,
			      awlen:    1,               // 2-beat burst
			      awsize:   axsize_8,
			      awburst:  axburst_incr,    // incrementing burst
			      awlock:   axlock_normal,
			      awcache:  awcache_dev_nonbuf,
			      awprot:   { axprot_2_data, axprot_1_non_secure, axprot_0_unpriv },
			      awqos:    0,
			      awregion: 0,
			      awuser:   0};

      AXI4_Wr_Data #(Wd_Id, Wd_Data, Wd_User)
      wr_data = AXI4_Wr_Data {wid:     rg_axi4_id,
			      wdata:   data [63:0],
			      wstrb:   '1,
			      wlast:   False,
			      wuser:   0};

      master_xactor.i_wr_addr.enq (wr_addr);
      master_xactor.i_wr_data.enq (wr_data);

      rg_master_wr_req_data1 <= data [127:64];
      rg_master_wr_req_beat0 <= False;

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_master_wr_reqs_beat0:", cur_cycle);
	 $display ("    ", fshow (wr_addr));
	 $display ("    ", fshow (wr_data));
      end
   endrule

   rule rl_master_wr_reqs_beat1 (! rg_master_wr_req_beat0);

      AXI4_Wr_Data #(Wd_Id, Wd_Data, Wd_User)
      wr_data = AXI4_Wr_Data {wid:     rg_axi4_id,
			      wdata:   rg_master_wr_req_data1,
			      wstrb:   '1,
			      wlast:   True,
			      wuser:   0};

      master_xactor.i_wr_data.enq (wr_data);

      rg_master_wr_req_beat0 <= True;

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_master_wr_reqs_beat1:", cur_cycle);
	 $display ("    ", fshow (wr_data));
      end
   endrule

   rule rl_master_wr_rsps;
      let wr_resp <- pop_o (master_xactor.o_wr_resp);
      Bool success = (wr_resp.bresp == axi4_resp_okay);
      accel.master_wr.response.put (success);

      if (verbosity > 0) begin
	 $display ("%0d: %m.rl_master_wr_rsps:", cur_cycle);
	 $display ("    ", fshow (wr_resp));
      end
   endrule

   // ================================================================
   // INTERFACE

   method Action init (Bit# (Wd_Id) axi4_id, Bit #(64) addr_base, Bit #(64) addr_lim);
      rg_axi4_id <= axi4_id;
      slave_xactor.reset;
      master_xactor.reset;
      accel.init (addr_base);
   endmethod

   interface master = master_xactor.axi_side;
   interface slave  = slave_xactor.axi_side;

   method Bool interrupt_req = accel.interrupt_req;
endmodule

// ================================================================

endpackage
