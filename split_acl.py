#!/usr/bin/env python
from __future__ import unicode_literals

import os
import sys
import re
#import getpass
#import time
#import ___ipaddress___						# IPaddress validation
#import ___cidr_convert___					# Convert CIDR to Network address and reverse
from pprint import pprint
from ciscoconfparse import CiscoConfParse
#from ciscoconfparse.ccp_util import IPv4Obj
#from collections import namedtuple
#import cidr_convert
import csv 						# CSV Export 

#Check Python version
if sys.version_info[0] >= 3:
	python3 = True
else:
	python3 = False


PRINT_REMARKS = False			# True for print to screen, False no print to screen
PRINT_OUTPUT = False 			# Print to screen - default False
EXPORT_REMARKS = False 			# Skip the remark lines in export output
#EXPORT_ACL_LINE = True   		# Export the original ACL line, when exporting to CSV not recommended ad filtering will be difficult
SPLIT_OBJECT_GROUPS = True		# 1 to loop trough object-group and printout rows
EXTRACT_OBJECT_GROUPS = True	# True is extract all object-group to single output (nested groeps not visible), output to JSON will alway be nested
FLATTEN_NESTED_LISTS = True		# True if the output of nested lists must be extracted to one list
SKIP_INACTIVE = True			# True to skip lines that are inactie (last word of ACL line)
SKIP_TIME_EXCEEDED = True		# Skip rules with time-ranges that have passed by
EXTEND_PORT_RANGES = True 		# When True the ranges will be added seperataly, from begin to end range port
debug = False

"""
ToDo:

* Validate processed items: first count ACL rows, compare at end with processed rows (count: remark, skipped + processed)
* Add function to validate next hop, and add to export
* find unused object-groups (only really unused, from inactive ACLs must remain in config )
"""

#OUTPUT_JSON_FILE = "split_acl.json"

#input_config_file = "confsmall.conf" 
input_config_file = "ciscoconfig.conf" 

# named tuples
#interface = namedtuple('interface', 'namedif')


def parseconfig(filename):
	return CiscoConfParse(filename, ignore_blank_lines=True,  syntax='asa')

class ValidationError(Exception):
    def __init__(self, message, errors):

        # Call the base class constructor with the parameters it needs
        super(ValidationError, self).__init__(message)

        # Now for your custom code...
        self.errors = errors
        pass

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

def flatten( alist ):
	# Flatten nested list to one list
     newlist = []
     for item in alist:
         if isinstance(item, list):
             newlist = newlist + flatten(item)
         else:
             newlist.append(item)
     return newlist

def is_obj_string(obj):
	if python3 == True:
		if isinstance(obj, str)== True:
			return True
		else:
			return False
	else: # Python 2
		if isinstance(obj, basestring)== True:
			return True
		else:
			return False


def get_acl_lines(parse, acl_name):
	"""
	Get ACL line by line and parse to split_acl_lines to analyse per word

	"""
	for acl_line in parse.find_objects(r'access-list\s'):
		if acl_name in acl_line.text:
			acl_line_number = acl_line.linenum
			acl_line = acl_line.text.split(' ', 2)[2]
			# First check if remark or ACL type
			if (acl_line.partition(' ')[0] == 'remark' and PRINT_REMARKS == True ) or acl_line.partition(' ')[0] == 'extended':
				print(acl_line_number), ":",
				print(acl_line)
				if (acl_line.partition(' ')[0] == 'remark' and EXPORT_REMARKS == True ) or acl_line.partition(' ')[0] == 'extended':
					# Go further and split ACL
					split_acl_lines(parse, acl_line)
			

def get_og_content(parse, og_name, og_type):
	#parse = parseconfig(input_config_file)
	#og_types: protocol, network, service
	# network-object 

	og_rows_processed = 0
	#if og_type == 'network' or og_type == 'service' or og_type == 'service-po':
	if og_type == 'network' or og_type == 'service':
		if (debug):
			print("OBJECT-GROUP CONTENT : object-group " + og_type.strip() +" " + og_name.strip())
		try:
			og_items = iter(parse.find_all_children('object-group '+ og_type.strip() +' '+ og_name.strip(), exactmatch=True))
			#itercars = iter(cars)
			next(og_items)
		except:
			#Try an protocol object group with same name, some service- OG (beginning ACL) have reference to protocol only
			try:
				og_items = iter(parse.find_all_children('object-group protocol '+ og_name.strip(), exactmatch=True))
				#itercars = iter(cars)
				next(og_items)
			except:
				
				print("ERROR: Object-group " + og_name.strip() + " not found for type " + og_type)
	if og_items != '':
		if og_type == 'service':
			all_og_items = {}
		else:
			all_og_items = list()
		# Loop trough items 
		for og_item in og_items:
			og_rows_processed = og_rows_processed + 1
			if (debug):
				print("OG_ROW_PROCESSING : "), og_rows_processed
			og_item_words_total = len(og_item.split())
			og_item_words = og_item.split()
			og_dst_ports = ''

			## NETWORK OG
			if og_type == 'network':
				if og_item_words[0] != 'description' and og_item_words[0] != 'group-object' :
					# Check wether new object, group is used or valid IPv4 address
					if is_ipv4(og_item_words[1]):
						# 2nd and 3rd word are subnet and netmask
						og_IP_item = og_item_words[1] + " " + og_item_words[2]
						all_og_items.append(og_IP_item)
					elif og_item_words[1] == 'host':
						all_og_items.append(og_item_words[2] + "  255.255.255.255")
					elif og_item_words[1] == 'object':
						if (debug):
							print("SEARCHING FOR OBJECT")
						## get object items
						all_og_items.append(get_object_content(parse, og_item_words[2], og_type))
					elif og_item_words[1] == 'network':
						print("TODO NETWORK TYPE")
					else:
						raise ValidationError("ERROR: object-group type " + og_item_words[1] + " not found" + og_type, "get_og_content")
						print("ERROR: object-group type " + og_item_words[1] + " not found" + og_type)
				elif og_item_words[0] == 'group-object':
					# Loop trough nested groups
					all_og_items.append(get_og_content(parse, og_item_words[1], og_type))
			# Type = service (OG in beginngin of ACL)
			elif og_type == 'service':
				#FIRST CHECK IF SERVICE GROUP OR PORT-OBJECT-GROUP
				# NEEDS TO BE ADDED THE SERVICE TYPES SEE : https://www.cisco.com/c/en/us/td/docs/security/asa/asa83/configuration/guide/config/ref_ports.html#wpxref39421
				if og_item_words[0] == 'service-object' and og_item_words[0] != 'description':
					if (debug):
						print("SERVICE-OBJECT "), og_item_words[1]
					
					# we have icmp, tcp or udp service-objects
					# for every different in protocol a new ACL Line is needed!!
					if og_item_words[1] == 'icmp':		# Service type icmp
						#Type ICMP possible
						if og_item_words_total > 2:
							og_dst_ports = og_item_words[2]
						#if no extra words in service-object than both directions are allowed
						
					elif og_item_words[1] == 'tcp' or og_item_words[1] == 'udp' or og_item_words[1] == 'tcp-udp':		# Service type tcp
						#check if one port or range
						if og_item_words[2] == 'destination' and  og_item_words[3] == 'eq': 
							og_dst_ports = og_item_words[4]
						elif og_item_words[2] == 'destination' and  og_item_words[3] == 'range': 
							# Range have two inputs, start and beginning
							og_dst_ports = og_item_words[4] + '-' + og_item_words[5]

					#else:
					#	raise ValidationError("ERROR: service-group type " + og_item_words[1] + " not found for type " + og_type, "get_og_content")
					#	print("ERROR: object-group type " + og_item_words[1] + " not found" + og_type)
				elif og_item_words[0] == 'port-object' and og_item_words[0] != 'description' :
					# we have icmp, tcp or udp service-objects
					if og_item_words[1] == 'eq':			# one port is
						og_dst_ports = og_item_words[2]
					elif og_item_words[1] == 'range':		# port-object range loop all items
						og_dst_ports = og_item_words[2] + '-' + og_item_words[3]
					else:
						raise ValidationError("ERROR: port-group type " + og_item_words[1] + " not found for type " + og_type, "get_og_content")
						print("ERROR: object-group type " + og_item_words[1] + " not found in " + og_type)							
				elif og_item_words[0] == 'group-object':
					print("NESTED SERVICE GROUP FOUND!!!!")
					# nested group - loop till end
					# NEEDS TO BE CORRECTED FOR SERVICE-GROUPS!!
					#og_dst_ports.append(get_og_content(parse, og_item_words[1], og_type))

				# UPDATE DICTIONARY
				new_dict_line = {'protocol': og_item_words[1], 'destination_port': og_dst_ports}
				all_og_items[og_rows_processed] = new_dict_line
				#all_og_items = new_dict_line
				

	if FLATTEN_NESTED_LISTS == True and og_type != 'service':
		all_og_items = flatten(all_og_items)
	
	if (debug):
		print ("RETURN OG_CONTENT FUNCTION : ")
		print(all_og_items)
	return all_og_items

def get_object_content(parse, object_name, o_type):
	#Instead of object-group there are also objects 
	#og_types: protocol, network, service
	# network-object 
	indent_space = "     "
	# Create empyt list
	all_object_items = list()
	if o_type == 'network' or o_type == 'service':
		o_items = iter(parse.find_all_children('^object '+ o_type + ' ' + object_name + '', exactmatch=True))
		#skip first item
		next(o_items)
		for o_item in o_items:
			o_item_words = o_item.split()
			#print(indent_space + o_item)
			if o_item_words[0] == 'subnet':
				#print(o_item_words[1])
				all_object_items.append(o_item_words[1] + " " + o_item_words[2])
			elif o_item_words[0] == 'host':
				all_object_items.append(o_item_words[1] + "  255.255.255.255")
			elif o_item_words[0] == 'description':
				o_item_desc = o_item[len("description "):]
			elif o_item_words[0] == 'service-object':
				print("SERVICE-OBJECT PART OF OG-SERVICE")
			elif o_item_words[0] == 'port-object':
				print("SERVICE-OBJECT PART OF PORT OG (ENDING OF ACL")	
			else:
				print("ERROR OBJECT " + o_item_words[0] +  " TYPE NOT FOUND")
	else:
		print("ERROR OBJECT TYPE " + o_type + " NOT SUPPORTED")

	return all_object_items

def get_acl_dst_port_range(acl_line, acl_port_range_begin):
	#split acl_line
	acl_length = len(acl_line.split())
	acl_words = acl_line.split()
	acl_range_ports = list()
	# loop tru word, add +1 because the range function stop 1 before last word (default)
	for i in range(acl_port_range_begin, acl_length+1):
		acl_range_ports.append(get_acl_line_word(acl_line, i).encode("ascii"))


	if FLATTEN_NESTED_LISTS == True:
		acl_range_ports = flatten(acl_range_ports)		
	#return a string
	return acl_range_ports

def get_acl_line_word(acl_line, word_nr):
	acl_words = acl_line.split()
	return acl_words[word_nr-1]

def split_acl_lines(parse, acl_line):	
	acl_length = len(acl_line.split())
	indent_space = "     "
	acl_words = acl_line.split()
	# FILTER LINES, DONT PROCESS FURTHER
	skip_this_line = False
	if SKIP_INACTIVE == True and (get_acl_line_word(acl_line, acl_length) == 'inactive'):
		skip_this_line = True
		print("SKIPPED! Inactive")
	# Check if a time filter is used and is exceeded
	if SKIP_TIME_EXCEEDED == True and (get_acl_line_word(acl_line, acl_length-1) == 'time-range'):
		skip_this_line = True
		# RUN FUNCTION TO CHECK TIME AND RETURN SKIP TRUE OR FALSE
		print("SKIPPED! time-range exceeded")
	# END FILTER
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
	acl_dst_in_og = False
	acl_dst_sn = ''
	acl_dst_nm = ''
	acl_dst_og = ''
	acl_dst_ports_in_og = False 	
	acl_dst_ports_og  = ''
	acl_dst_ports = ''

	# define empty variables
	acl_type = get_acl_line_word(acl_line, acl_type_section)
	if acl_type != 'remark' and not skip_this_line:
		acl_action = get_acl_line_word(acl_line, acl_action_section)
		
		acl_protocol = get_acl_line_word(acl_line, acl_protocol_section)
		#check if protocl is object-group
		if acl_protocol == 'object-group':
			acl_protocols_in_og = True
			acl_protocol_og = get_acl_line_word(acl_line, acl_protocol_section+1)
			acl_protocol_og_items = get_og_content(parse, acl_protocol_og, 'service') 	# section holds the object-group type. Can be 'service' or 'protocol

			# extend source and destination words
			acl_src_ip_section = acl_src_ip_section + 1
			acl_src_sn_section = acl_src_sn_section + 1
			acl_dst_ip_section = acl_dst_ip_section + 1
			acl_dst_sn_section = acl_dst_sn_section + 1
			acl_port_section = acl_port_section + 1
		else:
			acl_protocols_in_og = False

		# IF PROTOCOL = OBJECT-GROUP THE EXTRACTED LINE IN EXPORT NEEDS TO BE LOOPED FOR EVERY PROTOCOL / PORT

		# Get source
		acl_source_sn = get_acl_line_word(acl_line, acl_src_ip_section)
		if acl_source_sn == 'object-group':    
			acl_source_in_og = True
			acl_source_og = get_acl_line_word(acl_line, acl_src_ip_section+1)
			acl_source_og_items = get_og_content(parse, acl_source_og, 'network')
		elif acl_source_sn == 'object':    # Added object 19-4-18 
			acl_source_in_og = True
			acl_source_og = get_acl_line_word(acl_line, acl_src_ip_section+1)
			#acl_source_og_items = get_og_content(parse, acl_source_og, 'network')		
			acl_source_og_items = get_object_content(parse, acl_source_og, 'network')		
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
		if acl_dst_sn == 'object-group' or acl_dst_sn == 'object':   # Added object 19-4-18 
			acl_dst_in_og = True
			acl_dst_og = get_acl_line_word(acl_line, acl_dst_ip_section+1)
			acl_dst_og_items = get_og_content(parse, acl_dst_og, 'network')						
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

		# Get port settings
		#how many words
		acl_port_words = acl_length - acl_port_section
		# can be negative, only process further when positive
		if acl_port_words > 0:
			acl_total_port_words = acl_port_words + acl_port_section
			acl_port_first = get_acl_line_word(acl_line, acl_port_section)
			if acl_port_first == 'eq':
				# if first wordt is 'eq' one port will follow
				acl_dst_ports = get_acl_line_word(acl_line, acl_port_section + 1)
			# if first wordt is 'range' couple of words/ports will follow, space seperated
			if acl_port_first == 'range':
				# if range, loop trough words return list, start with first word
				acl_dst_ports = get_acl_dst_port_range(acl_line, acl_port_section+1)
			# if first wordt is 'object-range' a group (of groups) will follow
			if acl_port_first == 'object-group':
				acl_dst_ports_in_og = True
				acl_dst_ports_og = get_acl_line_word(acl_line, acl_port_section+1)
				# we need to extend the port object-name with the protocol by acl sdestination port groups
				acl_dst_ports_og = acl_dst_ports_og + ' ' + acl_protocol
				acl_dst_ports_og_items = get_og_content(parse, acl_dst_ports_og, 'service')
				if (debug):
					print("ACL DST PORTS ITEMS"), acl_dst_ports_og_items
				# CREATE EXTRA CHECK THAT THE OG HAVE SAME PROTOCOL MATCHING? NEED TO CHANGE function
				

			# if word is time-range followed by time setting. This is a temporary rule

	# VALIDATE INFO
	# Check : 
	# - IP address validation in Source - Destination
	# - Protocol check
	# - Port check
	# - No Service-Group names in output
	#
	# ToDo Validation


	# PRINT 
	if acl_type != 'remark' and not skip_this_line and (PRINT_OUTPUT):
		print("acl_type : " + acl_type)
		print("acl_action : " + acl_action)

		
		print("******* SOURCE: *******")
		if acl_source_og != '':
			print("acl_source_og : " + acl_source_og)
			if SPLIT_OBJECT_GROUPS == True:
				#convert list to string for print
				str_acl_source_og_items = '\n        '.join(map(str, acl_source_og_items))
				print(indent_space + "og_objects:" + str_acl_source_og_items)

		else:
			print("acl_source_sn : " + acl_source_sn)
			print("acl_source_nm : " + acl_source_nm) 
		print("****** DESTINATION: ******")
		if acl_dst_og != '':
			print("acl_dst_og : " + acl_dst_og)
			if SPLIT_OBJECT_GROUPS == True:
				#convert list to string for print
				str_acl_dst_og_items = '\n        '.join(map(str, acl_dst_og_items))
				print(indent_space + "og_objects:" + str_acl_dst_og_items)
			else:
				print(indent_space + "og_objects:" + acl_dst_og_items)
		else:
			print("acl_dst_sn : " + acl_dst_sn)
			print("acl_dst_nm : " + acl_dst_nm) 
		
		# DESTINATION PORTS
		if (acl_protocols_in_og):
			print("acl_protocol_og: " + acl_protocol_og)
			print(indent_space + "og_objects: ")
			#RETURN IS DICTIONARY, CREATE LOOP
			for key, item in acl_protocol_og_items.items():
				#print key, value
				print(indent_space + indent_space + "protocol " + item[u'protocol']),
				if item[u'destination_port'] != '':
					print("destination port " + item[u'destination_port'])
				else:
					print("")
			 	

		else:
#			print("acl_protocol : " + acl_protocol)

			if acl_dst_ports_og != '':
				print("******** PORTS: ********")
				print("acl_dst_ports_og : " + acl_dst_ports_og) 
				for key, item in acl_dst_ports_og_items.items():
					#print key, value
					if item[u'destination_port'] != '':
						print(indent_space + "protocol " + acl_protocol), 
						print("destination port " + item[u'destination_port'])
					else:
						print(indent_space + "PORT NOT FOUND")

			elif acl_dst_ports_og == '' and acl_port_words > 0:
				print("******** PORTS: ********")
				
				# Check if we have a string or list
				if is_obj_string(acl_dst_ports) == True:
					print(indent_space + "protocol" + acl_protocol), 
					print("destination port : "),
					print(acl_dst_ports)
				else:
					print(indent_space + "protocol" + acl_protocol), 
					print("destination port : "),
					for i in acl_dst_ports:
						print(i), 	
			
		# Else they come from starting object group

				

#		else:
#			print("NO PORTS IN DESTINATION ACL - SEE SERVICE GROUP FOR 2-WAY PORTS")

def createCSVOutput(fileName, keys, listOfLists):
    with open(fileName, 'w+') as f:
        w= csv.DictWriter(f, keys)
        w.writeheader()
        for row in listOfLists:
            w.writerow(row)

def main():
	print("Read config file")

	parse = parseconfig(input_config_file)
	pprint(parse)
	print("")

	print("      get ACL info")
	get_acl_lines(parse, "Interconnect_access_in")


#	acl_source_og = "BNS_Beheer_Segment"
#	acl_source_og_items = get_og_content(parse, acl_source_og, 'network')
#	if FLATTEN_NESTED_LISTS == True:
#		acl_source_og_items = flatten(acl_source_og_items)

	#print("")
	#pprint(acl_source_og_items)

if __name__ == "__main__":
	main()
