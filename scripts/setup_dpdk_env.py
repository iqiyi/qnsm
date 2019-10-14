#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
import sys
import subprocess

import configparser
import logging

ENV_CONF_PATH='/var/qnsm/dpdk_env.cfg'

def proc_shell(cmd, shell=True):
	proc = subprocess.Popen(cmd,stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=shell)
	return proc.communicate()[0]

def get_numa_node(nic_name):
	if None != nic_name:
		exe_str = "ethtool -i "+ nic_name + " | grep bus-info | awk '{print $2}'"
		bus_info = proc_shell(exe_str)
		bus_info = bus_info.split("\n")[0]
		return proc_shell("cat /sys/bus/pci/devices/" + bus_info + "/numa_node").split("\n")[0]

def set_hugepage(numa_node, nr_hugepages):
	if None == nr_hugepages:
		nr_hugepages = 10240
	if None != numa_node:
		proc_shell("echo "+ str(nr_hugepages) + \
		" > /sys/devices/system/node/node" + str(numa_node) + "/hugepages/hugepages-2048kB/nr_hugepages")

def bind_uio(RTE_SDK, RTE_TARGET, nic):
	if 0 == len(proc_shell('lsmod | grep uio')):
		proc_shell('modprobe uio')
	if 0 == len(proc_shell('lsmod | grep igb_uio')):
		proc_shell('insmod ' + RTE_SDK + '/' + RTE_TARGET + '/kmod/igb_uio.ko')
	if 0 < len(proc_shell('lsmod | grep igb_uio')):
		proc_shell('ifconfig ' + nic + ' down')
		proc_shell(RTE_SDK + '/tools/dpdk-devbind.py --bind=igb_uio ' + nic)

if __name__ == "__main__":
	if len(sys.argv) > 2:
		print("USAGE: %s conf_file" % sys.argv[0])
		sys.exit(1)
	if False == os.path.exists(ENV_CONF_PATH):
		if 2 == len(sys.argv):
			conf_file = sys.argv[1]
	else:
		conf_file = ENV_CONF_PATH
	if None == conf_file:
		print('ERR: conf file not exist')
		sys.exit(1)

	config = configparser.ConfigParser()
	config.read(conf_file)
	RTE_SDK = None
	RTE_TARGET = None
	has_var_section = config.has_section('VAR')
	if has_var_section:
		RTE_SDK=config.get('VAR', 'RTE_SDK')
		RTE_TARGET=config.get('VAR', 'RTE_TARGET')

	#if RTE var not exist, get from system env var
	if None == RTE_SDK or 0 == len(RTE_SDK):
		RTE_SDK = os.environ.get('RTE_SDK')
		RTE_TARGET = os.environ.get('RTE_TARGET')
	if None == RTE_SDK or 0 == len(RTE_SDK):
		print('ERR: RTE_SDK or RTE_TARGET undefined')
		sys.exit(1)

	nic = [None, None]
	nr_hugepages = [None, None]
	numa_node = [None, None]
	for i in range(0,2):
		nic[i] = config.get('NIC'+ str(i+1), 'name')
		if config.has_option('NIC' + str(i+1), 'nr_hugepages'):
			nr_hugepages[i] = int(config.get('NIC' + str(i+1), 'nr_hugepages'))
		if None != nic[i] and 0 < len(proc_shell('ifconfig ' + nic[i])):
			numa_node[i] = int(get_numa_node(nic[i]))
			set_hugepage(numa_node[i], nr_hugepages[i])
			bind_uio(RTE_SDK, RTE_TARGET, nic[i])
			
	if (None == numa_node[0]) and (None != numa_node[1]):
		set_hugepage(1 - numa_node[1], 1024)
	if (None == numa_node[1]) and (None != numa_node[0]):
		set_hugepage(1 - numa_node[0], 1024)
	if (numa_node[1] == numa_node[0]) and (None != numa_node[0]):
		set_hugepage(1 - numa_node[0], 1024)

	proc_shell('mkdir /mnt/huge ; mount -t hugetlbfs nodev /mnt/huge')

	#write RTE env var to conf file, in case of reboot
	if False == has_var_section:
		config = configparser.RawConfigParser()
		config.add_section('VAR')
		config.set('VAR', 'RTE_TARGET', RTE_TARGET)
		config.set('VAR', 'RTE_SDK', RTE_SDK)
		with open(conf_file, 'ab') as configfile:
			config.write(configfile)