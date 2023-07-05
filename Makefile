# SPDX-License-Identifier: GPL-2.0
#
# HyperEnclave kernel module.
#
# Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.

# Default target
all: modules

# Do not print "Entering directory ..."
MAKEFLAGS += --no-print-directory

# Module build
KDIR ?= /lib/modules/`uname -r`/build

modules clean:
	$(Q)$(MAKE) -C $(KDIR) M=$(PWD) $@

format:
	find . -name *.h -o -name *.c | xargs clang-format -style=file -i

.PHONY: modules clean format
