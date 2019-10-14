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
# enable as needed.
#
# TODO: use standard way to define compile flags.
#

#CFLAGS += -D 

CFLAGS += -include $(ROOTDIR)/include/qnsm_config.h

GCC_MAJOR = $(shell echo __GNUC__ | $(CC) -E -x c - | tail -n 1)
GCC_MINOR = $(shell echo __GNUC_MINOR__ | $(CC) -E -x c - | tail -n 1)
GCC_VERSION = $(GCC_MAJOR)$(GCC_MINOR)
