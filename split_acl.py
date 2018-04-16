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
#from collections import namedtuple
#import cidr_convert



PRINT_REMARKS = 0				# 1 for print to screen, other for not
SPLIT_OBJECT_GROUPS = 1			# 1 to loop trough object-group and printout rows
EXTRACT_OBJECT_GROUPS = 1		# 1 is extract all object-group to single output (nested groeps not visible), output to JSON will alway be nested

OUTPUT_JSON_FILE = "split_acl.json"

input_config_file = "interconnect.conf" 

# named tuples
#interface = namedtuple('interface', 'namedif')


def parseconfig(filename):
	return CiscoConfParse(filename)

def is_ipv4(ip):
	match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
	if not match:
		return False
	quad = []
	for number in match.groups():
		quad.append(int(number))
	if quad[0] < 1:
		return False
	for number in quad:
		if number > 255 or number < 0:
			return False
	return True

def get_acl_lines(parse, acl_name):
	for acl_line in parse.find_objects(r'access-list\s'):
		if acl_name in acl_line.text:
			print("")
			print(acl_line.linenum), ":", 
			#split line
			acl_line = acl_line.text.split(' ', 2)[2]
			print(acl_line)
			split_acl_lines(parse, acl_line)

def get_og_content(parse, og_name, og_type):
	#parse = parseconfig(input_config_file)
	#og_types: protocol, network, service
	# network-object 
	all_og_items = list()
	if og_type == 'network':
		#print("NETWORK OBJECTS :" + og_name)
		og_items = iter(parse.find_all_children('object-group network '+ og_name, exactmatch=True))
		#itercars = iter(cars)
		next(og_items)
		
		for og_item in og_items:
			
			og_item_words = og_item.split()
			if og_item_words[0] != 'description' and og_item_words[0] != 'group-object' :
				print(" " + og_item)
				#print (og_item_words[1])
				# Check wether new object, group is used or valid IPv4 address
				if is_ipv4(og_item_words[1]):
					#print("Is IPv4 : " + og_item_words[1])
					# 2nd and 3rd word are subnet and netmask
					og_IP_item = og_item_words[1] + " " + og_item_words[2]
					#print(og_IP_item)
					all_og_items.append(og_IP_item)
				elif og_item_words[1] == 'object':
					## get object items
					og_item_object = get_object_content(parse, og_item_words[2], og_type)
				elif og_item_words[1] == 'network':
					print("TODO NETWORK TYPE")
				else:
					print("ERROR: object-group type " + og_item_words[1] + " not found")
			elif og_item_words[0] == 'group-object':
				print(" " + og_item), 
				#now check first word is 'group-object'
				#print("GROUP-OBJECT")
				all_og_items.append(get_og_content(parse, og_item_words[1], 'network'))
	return all_og_items

def get_object_content(parse, object_name, o_type):
	#Instead of object-group there are also objects 
	#og_types: protocol, network, service
	# network-object 
	indent_space = "     "
	print("")
	print(indent_space + "finding objects for " + object_name)
	print("")
	all_object_items = list()
	if o_type == 'network':
		o_items = parse.find_all_children('^object network '+ object_name + '', exactmatch=True)
		for o_item in o_items:
			print(indent_space + o_item)


	return all_object_items


def get_acl_line_word(acl_line, word_nr):
	acl_words = acl_line.split()
	return acl_words[word_nr-1]

def split_acl_lines(parse, acl_line):	
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
			#get OG items for NETWORK type
			acl_source_og_items = get_og_content(parse, acl_source_og, 'network')
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

	parse = parseconfig(input_config_file)
	pprint(parse)
	print("")

#	print("      get ACL info")
#	get_acl_lines(parse, "Interconnect_access_in")


	acl_source_og = "BNS_Beheer_Segment"
	acl_source_og_items = get_og_content(parse, acl_source_og, 'network')
	print("")
	pprint(acl_source_og_items)

if __name__ == "__main__":
	main()
