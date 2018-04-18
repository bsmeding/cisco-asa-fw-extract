#!/usr/bin/env python

import os
import sys
import re
#import getpass
#import time
from pprint import pprint
from ciscoconfparse import CiscoConfParse
from ciscoconfparse.ccp_util import IPv4Obj
from collections import namedtuple

interface = namedtuple('interface', 'namedif')

def parseconfig(filename):
	return CiscoConfParse(filename)

def get_interfaces(parse):
	interfaces = []
	for intf_obj in parse.find_objects(r'^interf\s'):
		interfaces.append(intf_obj.text)
	return interfaces	

def get_nameif_interfaces(parse):
	interfaces = []
	interfaces = [obj for obj in parse.find_objects(r"^interf") \
    	if obj.re_search_children(r"nameif")]
	return interfaces

def get_acl_in(parse, nameif):
	#active_acls = parse.find_objects(r'accesss-group\s+(.*)\s+in\s+interface')
	for acl in parse.find_objects(r'access-group\s'):
		#print(acl)
		if nameif in acl.text:
			match = re.search(r"in interface (.*)$", nameif)
			#print(" ***** Match op " + acl.text)
			#acl_name = acl.text[len("access-group "):]
			acl_name = acl.text
			acl_name = acl_name.split(' ', 2)[1]
			#print(acl_name)
			return(acl_name)

def get_acl_out(parse, nameif):
	#active_acls = parse.find_objects(r'accesss-group\s+(.*)\s+in\s+interface')
	for acl in parse.find_objects(r'access-group\s'):
		#print(acl)
		if nameif in acl.text:
			match = re.search(r"out interface (.*)$", nameif)
			#print(" ***** Match op " + acl.text)
			#acl_name = acl.text[len("access-group "):]
			acl_name = acl.text
			acl_name = acl_name.split(' ', 2)[1]
			#print(acl_name)
			return(acl_name)

def get_acl_lines(parse, acl_name):
	for acl_line in parse.find_objects(r'access-list\s'):
		if acl_name in acl_line.text:
			#print(acl_line)
			#split line
			acl_line = acl_line.text.split(' ', 2)[2]
			print(acl_line)
			split_acl_lines(acl_line)


def split_acl_lines(acl_line):
	# FUNCTIE NIET AF -TEST IN EIGEN PY
	#print(acl_line),
	acl_line = acl_line.split(' ')
	#print(acl_line[0]),
	acl_type = acl_line[0]
	#check if line is extended or remark line, if remark this will the remark till overwritten
	if acl_type == 'remark':
		print("REMARK")
	if acl_line == 'extended':
		print("ACL LINE")
	#if acl_line != 'remark' and acl_line != 'extended':
	#	print("TYPE NOT FOUND")



def main():
	print("Read config file")

	parse = parseconfig("ciscoconfig.conf")
	pprint(parse)
	print("")

	interfaces = get_nameif_interfaces(parse)
	for intf_obj in interfaces:
		print("")
		# get the interface name (remove the interface command from the configuration line)
		intf_name = intf_obj.text[len("interface "):]
		print(intf_name)


		# search for the nameif 
		for cmd in intf_obj.re_search_children(r"^ nameif "):
			intf_nameif = cmd.text.strip()[len("nameif "):] 
        	print(" nameif " + intf_nameif)

        	# Get incoming ACL
        	print(" **** searching for incoming ACL for interface " + intf_nameif) + ": ", 
        	incoming_acl = get_acl_in(parse, intf_nameif)
	    	print(incoming_acl)

	    	if incoming_acl != None:
	    		print("      get ACL info")
	    		get_acl_lines(parse, incoming_acl)



			# Get outgoingACL
        	print(" **** searching for outgoing ACL for interface " + intf_nameif) + ": ", 
        	outgoing_acl = get_acl_out(parse, intf_nameif)
	    	print(outgoing_acl)




if __name__ == "__main__":
	main()
