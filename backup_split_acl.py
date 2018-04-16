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

PRINT_REMARKS = 0		# 1 for print to screen, other for not

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
			split_acl_lines(acl_line)

def get_acl_line_word(acl_line, word_nr):
	acl_words = acl_line.split()
	return acl_words[word_nr-1]

def split_acl_lines(acl_line):	
	acl_length = len(acl_line.split())
	acl_words = acl_line.split()
	acl_type = acl_words[0]
	
	#check if line is extended or remark line, if remark this will the remark till overwritten
	if acl_type == 'remark':
		remark_text = acl_line[len("remark "):]
		if PRINT_REMARKS == 1:
			print(acl_line),
			print("aantal woorden: ", acl_length)
			print("REMARK"),
			print(remark_text)
	if acl_type == 'extended':
		print(acl_line),
		print("aantal woorden: ", acl_length)
		print("ACL :")
		#acl_action = acl_words[1]
		acl_action = get_acl_line_word(acl_line, 2)
		print("  action :" + acl_action)
		if acl_action == 'permit' or acl_action == 'deny':
			#go further
			acl_protocol = get_acl_line_word(acl_line, 3)
			#acl_protocol = acl_words[2]
			protocols = ['ip', 'tcp', 'udp']
			if acl_protocol in protocols:
				print("  protocol : " + acl_protocol)
				# check source for host or subnet
				acl_word4 = get_acl_line_word(acl_line, 4)
				if acl_word4 == 'host':
					acl_source_host = get_acl_line_word(acl_line, 5)
					print("  source is host: " + acl_source_host)
				if acl_word4 == 'object-group':
					acl_source_og = acl_words[4]
					print("  source object-group: " + acl_source_og)
				if 'any' in acl_word4:
					print("  source: any")
				if acl_word4 != 'host' and acl_word4 != 'object-group' and not 'any' in acl_word4:
					acl_source_sn = get_acl_line_word(acl_line, 4)
					acl_source_nm = get_acl_line_word(acl_line, 5)
					#try acl_valid_source_sn = ipaddress.ip_address(acl_source_sn):
					#	try acl_valid_source_nm = ipaddress.ip_address(acl_source_nm):
					#		print("  source subnet :", acl_source_sn,  " " + acl_source_nm)
					#	except ValueError:
					#		print("  source netmasl not valid")
					#except ValueError:
					#		print("  source subnet not valid")		
					print("  source subnet : " + acl_source_sn + " " + acl_source_nm)



				# check where host / subnet belongs to


				# check where host / subnet next hop is (route table)
			if acl_protocol == 'object-group':
				print("  protocol in object-group : "),
				acl_protocol_og = get_acl_line_word(acl_line, 4)
				print(acl_protocol_og),
				# launch function to get object-group items
			if acl_protocol not in protocols and acl_protocol != 'object-group':
				print("ERROR! ACL protocol not found")					
		else:
			print("ERROR! ACL action not found")

	if acl_type != 'remark' and acl_type != 'extended':
		print("TYPE NOT FOUND")



def main():
	print("Read config file")

	parse = parseconfig("interconnect.conf")
	pprint(parse)
	print("")


	print("      get ACL info")
	get_acl_lines(parse, "Interconnect_access_in")



if __name__ == "__main__":
	main()
