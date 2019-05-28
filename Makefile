###  -*-Makefile-*-

# Copyright (c) 2019 Bluespec, Inc. All Rights Reserved

# ================================================================

.PHONY: help
help:
	@echo '    make  compile      Recompile the IP to Verilog (in dir Verilog_RTL)'
	@echo '                           NOTE: needs Bluespec bsc compiler'
	@echo ''
	@echo '    make  clean        Remove intermediate build-files'
	@echo '    make  full_clean   Restore to pristine state (pre-building anything)'

.PHONY: all
all: compile

# ================================================================
# Search path for bsc for .bsv files

BSC_PATH = src_Layer_2:src_Layer_1:src_Layer_0:BSV_Additional_Libs:+

# ----------------
# Top-level file and module

TOPFILE   ?= src_Layer_0/AXI4_Accel.bsv

# ================================================================
# bsc compilation flags

BSC_COMPILATION_FLAGS += \
	-keep-fires -aggressive-conditions -no-warn-action-shadowing -no-show-timestamps -check-assert \
	-suppress-warnings G0020    \
	+RTS -K128M -RTS  -show-range-conflict

# ================================================================
# Generate Verilog RTL from BSV sources (needs Bluespec 'bsc' compiler)

RTL_GEN_DIRS = -vdir Verilog_RTL  -bdir build_dir  -info-dir build_dir

build_dir:
	mkdir -p $@

Verilog_RTL:
	mkdir -p $@

.PHONY: compile
compile:  build_dir  Verilog_RTL
	@echo  "INFO: Verilog RTL generation ..."
	bsc -u -elab -verilog  $(RTL_GEN_DIRS)  -D FABRIC64 $(BSC_COMPILATION_FLAGS)  -p $(BSC_PATH)  $(TOPFILE)
	@echo  "INFO: Verilog RTL generation finished"

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~  */src_Layer*/*~  build_dir  obj_dir

.PHONY: full_clean
full_clean: clean
	rm  -r -f  build_dir  Verilog_RTL

# ================================================================
