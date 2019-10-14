# Copyright (C) 2019 iQIYI (www.iqiyi.com).
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
# Makefile for QNSM
#
MAKE	= make
CC 		= gcc
LD 		= ld

ROOTDIR = $(PWD)
SUBDIRS = src test

INSDIR  = /var/qnsm/
CONF_TEMPLATE := ddos-idps
ifeq ("$(origin T)", "command line")
CONF_TEMPLATE = $(T)
endif
export INSDIR
export ROOTDIR
export CONF_TEMPLATE

all: config
	for i in $(SUBDIRS); do $(MAKE) -C $$i || exit 1; done

config: $(ROOTDIR)/include/qnsm_config.h
	@echo "Configuration done"

$(ROOTDIR)/include/qnsm_config.h:
	$(shell chmod +x $(ROOTDIR)/scripts/gen-config-h.sh)
	$(ROOTDIR)/scripts/gen-config-h.sh $(ROOTDIR)/config \
		> $(ROOTDIR)/include/qnsm_config.h
	
clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean || exit 1; done
	-rm -f $(ROOTDIR)/include/qnsm_config.h
	
install:all
	-mkdir -p $(INSDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install || exit 1; done