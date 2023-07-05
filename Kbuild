# SPDX-License-Identifier: GPL-2.0
#
# HyperEnclave kernel module.
#
# Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.

define filechk_version
	$(src)/scripts/gen_version_h $(src)/
endef

version_h := $(obj)/include/generated/version.h
$(version_h): $(src)/Makefile FORCE
	$(call filechk,version)

ifeq ($(filter %/Makefile.clean,$(MAKEFILE_LIST)),)
$(obj)/driver: $(version_h)
endif

obj-m := driver/
subdir-ccflags-y := -Werror

ifeq ($(shell test $(VERSION) -ge 5 && test $(PATCHLEVEL) -ge 4 && echo 1),1)
clean-files := include/generated
else
clean-dirs := include/generated
endif
