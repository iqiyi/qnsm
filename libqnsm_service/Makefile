#   BSD LICENSE
#
#   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include $(RTE_SDK)/mk/rte.vars.mk
include $(QNSM_PATH)/config

# library name
LIB = libqnsm_service.a

#CFLAGS += -g -O0
CFLAGS += $(WERROR_FLAGS) -Wno-undef -I$(SRCDIR) -I$(QNSM_PATH)/include -I$(QNSM_PATH)/include/cfg 

ifeq ($(CONFIG_QNSM_LIBQNSM_IDPS), y)
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_idps_env.c
CFLAGS += -D HAVE_CONFIG_H -D QNSM_LIBQNSM_IDPS -I/usr/local/include/suricata -I/usr/include/nss3 -I/usr/include/nspr4
LDLIBS += -lsuri
endif

ifeq ($(CONFIG_DEBUG_QNSM), y)
CFLAGS += -D DEBUG_QNSM
endif

EXPORT_MAP := qnsm_service.map

LIBABIVER := 0

# all source are stored in SRCS-y
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_service.c
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_crm.c
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_msg.c
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_port.c
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_tbl_conf.c
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_kafka.c
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_dpi.c
SRCS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += qnsm_acl.c

# this lib needs eal and ring
DEPDIRS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += lib/librte_eal lib/librte_ring lib/librte_mempool lib/librte_mbuf
LDLIBS += -lrdkafka 

include $(RTE_SDK)/mk/rte.lib.mk
