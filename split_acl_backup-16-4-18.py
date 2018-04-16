#!/usr/bin/env python
from __future__ import unicode_literals

import os
import sys
import re
#import getpass
#import time
import ipaddress
from pprint import pprint
from ciscoconfparse import CiscoConfParse
from ciscoconfparse.ccp_util import IPv4Obj
from collections import namedtuple
import cidr_convert

PRINT_REMARKS = 0			# 1 for print to screen, other for not
SPLIT_OBJECT_GROUPS = 1		# 1 to loop trough object-group and printout rows	

# named tuples
interface = namedtuple('interface', 'namedif')


def parseconfig(filename):
	return CiscoConfParse(filename)


def get_acl_lines(parse, acl_name):
	for acl_line in parse.find_objects(r'access-list\s'):
		if acl_name in acl_line.text:
			print("")
			print(acl_line.linenum), ":", 
			#split line
			acl_line = acl_line.text.split(' ', 2)[2]
			print(acl_line)
			split_acl_lines(acl_line)

def get_acl_line_word(acl_line, word_nr):
	acl_words = acl_line.split()
	return acl_words[word_nr-1]

def split_acl_lines(acl_line):	
	acl_length = len(acl_line.split())
	acl_words = acl_line.split()
	indent_space = "     "
	# Set default section names in ACL row (space seperated) they can change based on object-groups
	acl_type_section = 1
	acl_action_section = 2
	acl_protocol_section =3
	acl_src_ip_section = 4
	acl_src_sn_section = 5
	acl_dst_ip_section = 6
	acl_dst_sn_section = 7
	acl_port_section = 8
	#check if line is extended or remark line, if remark this will the remark till overwritten

	# define empty variables
	acl_type = ''
	acl_action = ''
	acl_protocols_in_og = False
	acl_protocol_og = ''
	acl_protocol = ''
	acl_source_in_og = False
	acl_source_sn = ''
	acl_source_nm = ''
	acl_source_og = ''
	acl_dst__in_og = False
	acl_dst_sn = ''
	acl_dst_nm = ''
	acl_dst_og = ''


	# define empty variables
	acl_type = get_acl_line_word(acl_line, acl_type_section)
	if acl_type != 'remark':
		acl_action = get_acl_line_word(acl_line, acl_action_section)
		
		acl_protocol = get_acl_line_word(acl_line, acl_protocol_section)
		#check if protocl is object-group
		if acl_protocol == 'object-group':
			acl_protocols_in_og = True
			acl_protocol_og = get_acl_line_word(acl_line, acl_protocol_section+1)
			# extend source and destination words
			acl_src_ip_section = acl_src_ip_section + 1
			acl_src_sn_section = acl_src_sn_section + 1
			acl_dst_ip_section = acl_dst_ip_section + 1
			acl_dst_sn_section = acl_dst_sn_section + 1
			acl_port_section = acl_port_section + 1
		else:
			acl_protocols_in_og = False

		# Get source
		acl_source_sn = get_acl_line_word(acl_line, acl_src_ip_section)
		if acl_source_sn == 'object-group':
			acl_source_in_og = True
			acl_source_og = get_acl_line_word(acl_line, acl_src_ip_section+1)
		elif acl_source_sn == 'host':
			## Next item is host IP and not subnetmask. We generate default subnetmask
			acl_source_sn = get_acl_line_word(acl_line, acl_src_sn_section)
			acl_source_nm = '255.255.255.255'
		elif 'any' in acl_source_sn:	# check wordt as it can be any or any4 or any6
			## Next item is host IP and not subnetmask. We generate default subnetmask
			acl_source_sn = '0.0.0.0'
			acl_source_nm = '0.0.0.0'
			# rest of the word indexes -1
			acl_dst_ip_section = acl_dst_ip_section - 1
			acl_dst_sn_section = acl_dst_sn_section - 1
			acl_port_section = acl_port_section - 1
		else:
			acl_source_in_og = False
			acl_source_nm = get_acl_line_word(acl_line, acl_src_sn_section)
		
		# Get destination
		acl_dst_sn = get_acl_line_word(acl_line, acl_dst_ip_section)
		if acl_dst_sn == 'object-group':
			acl_dst_in_og = True
			acl_dst_og = get_acl_line_word(acl_line, acl_dst_ip_section+1)
		elif acl_dst_sn == 'host':
			## Next item is host IP and not subnetmask. We generate default subnetmask
			acl_dst_sn = get_acl_line_word(acl_line, acl_dst_sn_section)
			acl_dst_nm = '255.255.255.255'
		elif 'any' in acl_dst_sn:	# check wordt as it can be any or any4 or any6
			## Next item is host IP and not subnetmask. We generate default subnetmask
			acl_dst_sn = '0.0.0.0'
			acl_dst_nm = '0.0.0.0'
			# rest of the word indexes -1
			acl_port_section = acl_port_section - 1			
		else:
			acl_dst_in_og = False
			acl_dst_nm = get_acl_line_word(acl_line, acl_dst_sn_section)


	if acl_type != 'remark':
		print("acl_type : " + acl_type)
		print("acl_action : " + acl_action)
		if (acl_protocols_in_og):
			print("acl_protocol_og: " + acl_protocol_og)
			if SPLIT_OBJECT_GROUPS == 1:
				print(indent_space + "og_objects:")
		else:
			print("acl_protocol : " + acl_protocol)
		
		print("******* SOURCE: *******")
		if acl_source_og != '':
			print("acl_source_og : " + acl_source_og)
			if SPLIT_OBJECT_GROUPS == 1:
				print(indent_space + "og_objects:")

		else:
			print("acl_source_sn : " + acl_source_sn)
			print("acl_source_nm : " + acl_source_nm) 
		print("****** DESTINATION: ******")
		if acl_dst_og != '':
			print("acl_dst_og : " + acl_dst_og)
			if SPLIT_OBJECT_GROUPS == 1:
				print(indent_space + "og_objects:")
		else:
			print("acl_dst_sn : " + acl_dst_sn)
			print("acl_dst_nm : " + acl_dst_nm) 
		print("******** PORTS: ********")



def main():
	print("Read config file")

	parse = parseconfig("interconnect.conf")
	pprint(parse)
	print("")


	print("      get ACL info")
	get_acl_lines(parse, "Interconnect_access_in")



if __name__ == "__main__":
	main()
