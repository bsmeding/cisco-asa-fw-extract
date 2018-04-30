#!/usr/bin/env python

import os
import sys
import re
from pprint import pprint
from ciscoconfparse import CiscoConfParse

#Check Python version
if sys.version_info[0] >= 3:
	python3 = True
else:
	python3 = False

def parseconfig(filename):
	return CiscoConfParse(filename)

def get_interfaces(parse):
	"""
	Return all interfaces
	"""
	interfaces = []
	for intf_obj in parse.find_objects(r'^interf\s'):
		interfaces.append(intf_obj.text)
	return interfaces	

def get_nameif_interfaces(parse):
	"""
	Terung all interfaces with nameif configured
	"""

	interfaces = []
	interfaces = [obj for obj in parse.find_objects(r"^interf") \
    	if obj.re_search_children(r"nameif")]
	return interfaces

def get_acl_in(parse, nameif):
	#active_acls = parse.find_objects(r'accesss-group\s+(.*)\s+in\s+interface')
	for acl in parse.find_objects(r'access-group\s'):
		#print(acl)
		if nameif in acl.text and 'in interface' in acl.text:
			#print(acl.text)
			acl_name = acl.text
			acl_name = acl_name.split(' ', 2)[1]
			#print(acl_name)
			return(acl_name)

def get_acl_out(parse, nameif):
	#active_acls = parse.find_objects(r'accesss-group\s+(.*)\s+in\s+interface')
	for acl in parse.find_objects(r'access-group\s'):
		#print(acl)
		if nameif in acl.text and 'out interface' in acl.text:
			#print(acl.text)
			acl_name = acl.text
			acl_name = acl_name.split(' ', 2)[1]
			#print(acl_name)
			return(acl_name)

def intf_acl_to_dict(parse):
	interface_acl_dict = dict()
	"""
	Get all interfaces from Cisco ASA configuration, add the 'nameif'-name and match incoming and outgoing ACL's
	Return dictionary with: (sub)interface, nameif-name, acl_in, acl_out

	required sub-function:
	* get_nameif_interfaces
	* get_acl_in
	* get_acl_out
	"""
	# Get all interfaces in list where nameif is configured
	interfaces = get_nameif_interfaces(parse)
 
	# Loop trough these interfaces and try to find
	for intf_obj in interfaces:
		# get the interface name (remove the interface command from the configuration line)
		intf_name = intf_obj.text[len("interface "):]

		# Get nameif name:
		for cmd in intf_obj.re_search_children(r"^ nameif "):
			intf_nameif = cmd.text.strip()[len("nameif "):] 

			#Get incomping ACL
			incoming_acl = get_acl_in(parse, intf_nameif)
			#Get outgingin ACL
			outgoing_acl = get_acl_out(parse, intf_nameif)

		
			#Add to dictionary
			new_dict_line = {'nameif': intf_nameif,
				'acl_in': incoming_acl,
				'acl_out': outgoing_acl}
			interface_acl_dict[intf_name] = new_dict_line

	return interface_acl_dict



def main():
	print("Read config file")

	parse = parseconfig("ciscoconfig.conf")
	pprint(parse)
	print("")

	# Get insterfaces
	all_intfs = intf_acl_to_dict(parse)
	for key, item in all_intfs.items():
		print(key, item)
			


if __name__ == "__main__":
	main()
