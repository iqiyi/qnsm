# Copyright (C) 2017 iQIYI (www.iqiyi.com).
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

#
# Makefile for qnsm unit test
#

#DEBUG := 1		# enable for debug
include $(ROOTDIR)/config

TARGET := qnsm-test

DATE_STRING := $(shell date +%Y.%m.%d.%H:%M:%S)

# same path of THIS Makefile
SRCDIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

include $(ROOTDIR)/dpdk.mk
include $(ROOTDIR)/config.mk

INCDIRS += -I $(SRCDIR)/../include -I $(SRCDIR)/../include/cfg -I $(SRCDIR)/../src

CFLAGS += -Wall -Wstrict-prototypes -Wno-pointer-sign -Wno-unused-but-set-variable -Wno-unused-function -Wno-implicit-function-declaration -mcmodel=medium

ifeq ($(CONFIG_QNSM_LIBQNSM_IDPS), y)
INCDIRS += -I/usr/local/include/suricata -I/usr/include/nss3 -I/usr/include/nspr4
CFLAGS += -D HAVE_CONFIG_H
LIBS += -ljansson -lpcre -lhtp -lyaml -lmagic -lnss3 -lnspr4 -lsuri
endif

ifeq ($(shell test $(GCC_VERSION) -ge 70 && echo 1), 1)
	CFLAGS += -Wno-format-truncation
	CFLAGS += -Wno-stringop-truncation
	CFLAGS += -Wstringop-overflow=0
endif

ifeq ($(DEBUG),)
	CFLAGS += -O3
else
	CFLAGS += -g -O0
endif

LIBS += -lpthread -lrdkafka -lxml2 -lpcap

CFLAGS += $(INCDIRS) $(LIBS)

OBJS := $(shell find $(SRCDIR) -name '*.c' | sort)
OBJS += ../src/util.c ../src/cJSON.c ../src/cpu_core_map.c ../src/parser.c ../src/config_parse.c ../src/config_check.c
OBJS += ../src/qnsm_decode.c ../src/qnsm_cfg.c
ifeq ($(CONFIG_QNSM_LIBQNSM_IDPS), y)
OBJS += ../src/qnsm_idps_core.c ../src/qnsm_idps_shell.c
endif
OBJS += $(shell find $(SRCDIR)/../src/protos -name '*.c' | sort)
OBJS := $(patsubst %.c,%.o,$(OBJS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@$(CC) $(CFLAGS) $^ -o $@
	@echo "  $(notdir $@)"

%.o: %.c
	@$(CC) -c $(CFLAGS) $< -o $@
	@echo "  $(notdir $@)"

clean:
	find $(SRCDIR) -name '*.o' | xargs rm -f
	rm -f ./$(TARGET)

install:
	install -m 744 $(TARGET) $(INSDIR)
