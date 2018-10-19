#!/usr/bin/env python
from __future__ import unicode_literals

import os
import glob
import sys
import re
import itertools							# To combine list and all permutations
import csv 						# CSV Export 
from __routing__ import *
from pprint import pprint
from ciscoconfparse import CiscoConfParse
# Need:  pip install pandas
import pandas as pd

# Import ipaddress library based on Python version (2.x of 3.2 = ipaddr >3.2 ipaddres) used to calculate ip addresses in range
try:
    from ipaddress import ip_address
except ImportError:
    from ipaddr import IPAddress as ip_address

from netaddr import *

#Check Python version
if sys.version_info[0] >= 3:
	python3 = True
else:
	python3 = False


PRINT_REMARKS = False			# True for print to screen, False no print to screen. Default: False
PRINT_LINES = False 			# Print line info. Default: False
PRINT_FULL_OUTPUT = False 		# Print full extract info (debug). Default: False
debug = False 					# Debug mode - high print output! Default: False
PRINT_CURRENT_LINE = False 		# Print only current line processing
EXPORT_TO_CSV = True 			# Export ACL Lines to CSV. Default: True, otherwise to screen output
EXPORT_REMARKS = False 			# Skip the remark lines in export output. Default: False
EXPORT_ORIGINAL_LINE = True 	# Export the original ACL line (takes longer, and more export data). Default: True
FLATTEN_NESTED_LISTS = True		# True if the output of nested lists must be extracted to one list   << AFTER CHANGING TO DICTS THIS IS NOT WORKING ANYMORE !!!!!! CHECK. Default: True
SKIP_INACTIVE = True			# True to skip lines for printing that are inactive (last word of ACL line). Default: True
EXTEND_PORT_RANGES = False 		# When True the ranges will be added seperataly, from begin to end range port. Other it will be printed as <port_start>-<port_end>   << NEEDS TO BE CHECKED. Default: True
CALCULATE_NEXT_HOP_INFO = True 	# Calculate next hop interface, ip and route prio. Note that this will need some time as it will calculate for each row!. Default: False
EXPORT_CHANGE_PORT_TO_NUMBER = True 	# Default: True
SKIP_TIME_EXCEEDED = False		# Skip rules with time-ranges that have passed by NOT IMPLEMENTED YET!!. Default: False
CREATE_DICT = True 				# Maybe remove! Default: True
SHOW_SPLIT_LINE_OUTPUT = False
#EXPORT_ACL_SEPERATE_FILES = False 	# Export each ACL to separate file


input_dir = 'conf_input'

#output_csv_file = "acl_seperated.csv"
output_dir = 'acl_output'
output_dir = './' + output_dir

"""
ToDo:

* Validate processed items: first count ACL rows, compare at end with processed rows (count: remark, skipped + processed)
* Add function to validate next hop, and add to export
* find unused object-groups (only really unused, from inactive ACLs must remain in config )

	# VALIDATE INFO
	# Check : 
	# - IP address validation in Source - Destination
	# - Protocol check
	# - Port check
	# 
	#
	# ToDo Validation

# Export CSV will be:
source_host_id : 192.168.14.15
source_sn_id : 255.255.255.255
source_intf: <incomming interface name, based on routing table>
dest_host_id : 172.16.13.0
dest_sn_id : 255.255.255.0
dest_intf: <destination interface name, based on routing table entries>
dest_next_hop : next IP to forward packets to
dest_protocol : 
dest_port : 

"""







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

def is_obj_int(obj):	
	if python3 == True:
		if isinstance(obj, int)== True:
			return True
		else:
			return False
	else: # Python 2
		if isinstance(obj, (int, long))== True:
			return True
		else:
			return False

def get_og_type_by_name(og_name):
	# Returns the OG type based on og_items_dict
	for og_item in og_items:
		if og_item['og_name'] == og_name:
			return og_item['og_type']

def get_og_original_line_by_name(og_name):
	# Returns the OG type based on og_items_dict
	for og_item in og_items:
		if og_item['og_name'] == og_name:
			return og_item['original_og_row']

def create_o_dict(parse):
	global o_items
	o_items = dict()
	for o_item in parse.find_objects(r'^object\s'):
		o_item_words = o_item.text.split()
		o_type = o_item_words[1]
		o_name = o_item_words[2]
		if o_item_words[0] != 'description':
			o_items[o_name] = ({'original_o_row': o_item.text,'o_type': o_type})

def create_og_dict(parse):
	global og_items
	og_items = dict()
	for og_item in parse.find_objects(r'^object-group\s'):
		og_item_words = og_item.text.split()
		og_type = og_item_words[1]
		og_name = og_item_words[2]
		if len(og_item_words) >3:
			og_protocol = og_item_words[3]
		else:
			og_protocol = ''
		og_items[og_name] = ({'original_og_row': og_item.text,'og_type': og_type, 'og_protocol': og_protocol})

def get_acl_lines(parse, total_acl_lines, acl_name, acl_interface, acl_direction):
	"""
	Get ACL line by line and parse to split_acl_lines to analyse per word

	"""

	parsed_remark_lines = 0
	parsed_acl_lines = 0
	parsed_unknown_lines = 0
	# Create empty dictionary for object-groups - global so every module can use the items. And in de get_acl_lines so every new config will recreate the dict

	create_o_dict(parse)
	create_og_dict(parse)

	# Create ympty Dictionary for export
	acl_line_dict = dict()
	
	processed_acl_lines = dict()
	#pprint(og_items)
	processed_acl_id = 0
	for acl_line in parse.find_objects(r'access-list\s'):
		
		if acl_name in acl_line.text:
			# Declare ACL line number for index and skip first part of defualt text in ACL line
			acl_line_number = acl_line.linenum
			acl_line = acl_line.text.split(' ', 2)[2]
			
			#Start processed item logbook
			processed_acl_id += 1
			processed_acl_lines[processed_acl_id] = ({'acl_name': acl_name, 'acl_interface': acl_interface, 'acl_line_number': acl_line_number,'acl_line_child': '', 'acl_type': acl_line.partition(' ')[0], 'original_acl_line': acl_line,'acl_processed': False, 'reason':''})

			# First check if remark or ACL type
			if acl_line.partition(' ')[0] == 'remark':
				parsed_remark_lines = parsed_remark_lines + 1
				
				if (PRINT_REMARKS == True and PRINT_LINES == True) or (debug):
					print(acl_line_number), ":",
					print(acl_line)
				if EXPORT_REMARKS == True:
					total_acl_lines += 1	
					# Go further and split ACL
					new_dict_line = {'acl_line_number': acl_line_number, \
						'acl_line_child': '', \
						'acl_type': '', \
						'acl_action': '', \
						'acl_interface': acl_interface, \
						'acl_direction': acl_direction, \
						'acl_name': '', \
						'inactive': '', \
						'acl_source_cidr': '', \
						'acl_source_protocol': '', \
						'acl_source_port': '', \
						'acl_dst_cidr': '', \
						'acl_dst_protocol': '', \
						'acl_dst_port': '', \
						'acl_logging': '', \
						'acl_interface': '', \
						'acl_logging_severity': '', \
						'original_acl_line': '' \
						}
					acl_line_dict[total_acl_lines] = new_dict_line

					#Update processed item logbook, item processed now
					processed_acl_lines[processed_acl_id].update({'acl_processed': True})
					if EXPORT_ORIGINAL_LINE == True:
						acl_line_dict[total_acl_lines].update({'original_acl_line': acl_line})	

				else:
					processed_acl_lines[processed_acl_id].update({'reason': 'export_remark is False'})

					
			elif acl_line.partition(' ')[0] == 'extended':
				if (PRINT_LINES) or (debug):
					print(acl_line_number), ":",
					print(acl_line)
				acl_line_child = 0
				parsed_acl_lines = parsed_acl_lines + 1	
				total_list, acl_line_logged, acl_line_logged_severity, acl_line_inactive, source_ports_in_list, protocol_in_list, protocol_to_dest_port, acl_type, acl_action = split_acl_line(parse, acl_line, acl_line_number, acl_line_dict)
				# First set response processed line to false, maybe overwrite when there is information back from this lines
				processed_acl_lines[processed_acl_id].update({'acl_processed': False})
				processed_acl_lines[processed_acl_id].update({'reason': 'No input back from split_acl_lines'})


				#Add items to Dictionary
				for item in total_list:
					total_acl_lines += 1
					#print(total_acl_lines)
					#print(acl_line_number)
					acl_line_child += 1
					new_dict_line = {'acl_line_number': acl_line_number, \
						'acl_line_child': acl_line_child, \
						'acl_type': acl_type, \
						'acl_action': acl_action, \
						'acl_interface': acl_interface, \
						'acl_direction': acl_direction, \
						'acl_name': acl_name, \
						'inactive': acl_line_inactive, \
						'acl_source_cidr': item[0], \
						'acl_source_protocol': '', \
						'acl_source_port': '', \
						'acl_dst_cidr': item[1], \
						'acl_dst_protocol': '', \
						'acl_dst_port': '', \
						'acl_logging': acl_line_logged, \
						'acl_interface': acl_interface, \
						'acl_logging_severity': acl_line_logged_severity, \
						'original_acl_line': '' \
						}
					acl_line_dict[total_acl_lines] = new_dict_line
					if (source_ports_in_list):
						#print("SOURCE PORTS USED ")
						acl_line_dict[total_acl_lines].update({'acl_source_protocol': item[1]})
						acl_line_dict[total_acl_lines].update({'acl_source_port': item[2]})
					else:
						acl_line_dict[total_acl_lines].update({'acl_dst_protocol': item[1]})
						acl_line_dict[total_acl_lines].update({'acl_dst_port': item[2]})
					if EXPORT_ORIGINAL_LINE == True:
						acl_line_dict[total_acl_lines].update({'original_acl_line': acl_line})						

					#Update processed item logbook, item processed now
					processed_acl_lines[processed_acl_id].update({'acl_line_child': acl_line_child})
					processed_acl_lines[processed_acl_id].update({'acl_processed': True})
					processed_acl_lines[processed_acl_id].update({'reason': ''})

			else:
				parsed_unknown_lines = parsed_unknown_lines + 1
				print("ERROR! Unkown ACL type!")

	# OLD DIRECT EXPORT TO CSV FILE
	#export_dict_to_csv_old(acl_line_dict, acl_name)

	# Print unprocessed acl_lines:


	return (total_acl_lines, parsed_remark_lines, parsed_acl_lines, parsed_unknown_lines, acl_line_dict, processed_acl_lines)

def split_acl_line(parse, acl_line, acl_line_number, dict_to_update):

	# Create empty variables for return
	acl_type = ''
	acl_action = ''
	acl_protocol_list = list()
	#acl_protocol = ''
	acl_source_IP_list = list()
	acl_have_source_protocols = False
	acl_source_port_list = list()
	acl_destination_IP_list = list()
	acl_destination_port_list = list()
	acl_line_logged = False
	acl_line_logged_severity = ''
	acl_line_inactive = False

	# 
	acl_length = len(acl_line.split())
	indent_space = "     "
	acl_words = acl_line.split()
	ogs_in_acl_line = 0
	
	#print(acl_words)
	
	# Create new variables from this line
	acl_type = acl_words[0]
	acl_action = acl_words[1]

	next_og_source_IP_og = True 			# If first OG is network type, this become true
	og_name = ''
	og_info = ''
	og_original_line = ''
	#Next wordt can be: protocol or objec-group - first filter protocol


	if acl_words[acl_length-1] == 'inactive':
		acl_line_inactive = True
	if acl_words[2] == 'object-group':
		#protocol is in object-group 
		# can also been source network
		#print("protocol in object-group or source network")
		og_name = acl_words[3]
		og_info = og_items.get(og_name, "NOT FOUND")
		og_original_line = og_info['original_og_row']
		next_og_source_og = False
		if og_info['og_type'] == 'network':
			next_og_source_IP_og = False 		# Next OG cannot be an source IP network
			acl_destination_port_list = get_og_items_flattened(parse, og_original_line, og_info['og_type'])
		elif og_info['og_type'] == 'protocol':
			acl_protocol_list = get_og_items_flattened(parse, og_original_line, og_info['og_type'])
		else:
			next_og_source_IP_og = True 		# Next OG must be source OG as we alreade have protocol type OG
			acl_destination_port_list = get_og_items_flattened(parse, og_original_line, og_info['og_type'])
		next_word_index = 4

	elif acl_words[2] == 'object':
		o_name = acl_words[3]
		o_info = o_items.get(o_name, "NOT FOUND")
		o_original_line = o_info['original_o_row']
		#print("OBJECT FOUND : " + o_original_line + " BETA! CHECK CORRECT OUTPUT!!")
		new_item = get_object_item(parse, o_name, o_info['o_type'])
		if isinstance(new_item, (list,)):
			for item in new_item:
				all_object_groups_items.append(item)
		else:
			all_object_groups_items.append(new_item)
		next_word_index = next_word_index + 2
	else:
		# protocol is known for all next ports
		acl_protocol_list.append(acl_words[2])
		next_word_index = 3		

	#print(acl_protocol_list)
	
	# Go further, next_word_index = ...
	if acl_words[next_word_index] == 'object-group':
		og_name = acl_words[next_word_index+1]
		og_info = og_items.get(og_name, "NOT FOUND")
		og_original_line = og_info['original_og_row']
		og_type = og_info['og_type']

		if next_og_source_IP_og == True:
			if og_type == 'network':
				#this must be source
				acl_source_IP_list = get_og_items_flattened(parse, og_original_line, og_type)
				#print("dit is source netwerk OG : " + og_name)
				#print(acl_source_IP_list)
			else:
				print("|-->>> ERROR | No OG network type when expected")
		else:
			#this will be source port OG, or destinaG
			print("uitzoeken source PORT OG of DEST IP OG")
		next_word_index = next_word_index + 2
	elif acl_words[next_word_index] == 'object':
		o_name = acl_words[next_word_index+1]
		o_info = o_items.get(o_name, "NOT FOUND")
		o_original_line = o_info['original_o_row']
		#print("OBJECT FOUND : " + o_original_line + " BETA! CHECK CORRECT OUTPUT!!")
		new_item = get_object_item(parse, o_name, o_info['o_type'])
		if isinstance(new_item, (list,)):
			for item in new_item:
				acl_source_IP_list.append(item)
		else:
			acl_source_IP_list.append(new_item)
		next_word_index = next_word_index + 2
	else:
		#protocol list not empty, so protocols already known. Now we excpect source_subnet or 'host'
		if is_ipv4(acl_words[next_word_index]) and is_ipv4(acl_words[next_word_index+ 1]):
			#we get source ip / sn
			acl_source_IP_list.append(acl_words[next_word_index] + "/" + str(netmask_to_cidr(acl_words[next_word_index + 1])))
			next_word_index = next_word_index + 2
		elif acl_words[next_word_index] == 'host':
			# one IP will follow from source host IP
			acl_source_IP_list.append(acl_words[next_word_index+1] + "/32")
			next_word_index = next_word_index + 2
		elif acl_words[next_word_index] == 'any' or acl_words[next_word_index] == 'any4' or acl_words[next_word_index] == 'any6':
			# one IP will follow from source host IP
			acl_source_IP_list.append("0.0.0.0/0")
			next_word_index = next_word_index + 1
		#print(acl_source_IP_list)
		else:
			print("|-->>> ERROR | no type found in word " + acl_words[next_word_index])
			print("|            | " + acl_line)
	
	

	#print(acl_words[next_word_index])
	# If Object or Object-group this must be the destination
	if acl_words[next_word_index] == 'object-group':
		og_name = acl_words[next_word_index+1]
		og_info = og_items.get(og_name, "NOT FOUND")
		og_original_line = og_info['original_og_row']
		og_type = og_info['og_type']

		if og_type == 'network':
			#this must be destination
			acl_destination_IP_list = get_og_items_flattened(parse, og_original_line, og_type)
			next_word_index = next_word_index + 2
		elif og_type == 'service':
			acl_destination_port_list = get_og_items_flattened(parse, og_original_line, og_type)
			next_word_index = next_word_index + 2
		else:
			print("|-->> ERROR | No OG network type when expected")
	elif acl_words[next_word_index] == 'object':
		o_name = acl_words[next_word_index+1]
		o_info = o_items.get(o_name, "NOT FOUND")
		o_original_line = o_info['original_o_row']
		#print("OBJECT FOUND : " + o_original_line + " BETA! CHECK CORRECT OUTPUT!!")
		new_item = get_object_item(parse, o_name, o_info['o_type'])
		if isinstance(new_item, (list,)):
			for item in new_item:
				acl_destination_IP_list.append(item)
		else:
			acl_destination_IP_list.append(new_item)
		next_word_index = next_word_index + 2
	else:
	#protocol list not empty, so protocols already known. Now we excpect source_subnet or 'host'
		if acl_words[next_word_index] == 'any' or acl_words[next_word_index] == 'any4' or acl_words[next_word_index] == 'any6':
			# one IP will follow from source host IP
			acl_destination_IP_list.append("0.0.0.0/0")
			next_word_index = next_word_index + 1
		elif acl_words[next_word_index] == 'eq':
			# Source ports are used
			acl_source_port_list.append(str(acl_protocol_list[0]) + ":" + str(replace_port_name_to_number(acl_words[next_word_index+1])))
			#print("source protocols : " + str(acl_protocol_list) + " port : " + str(acl_source_port_list))
			acl_have_source_protocols = True
			next_word_index = next_word_index + 2
		elif acl_words[next_word_index] == 'host':
			# one IP will follow from source host IP
			acl_destination_IP_list.append(acl_words[next_word_index+1] + "/32")
			next_word_index = next_word_index + 2
		elif is_ipv4(acl_words[next_word_index]) and is_ipv4(acl_words[next_word_index+ 1]):
			#we get source ip / sn
			acl_destination_IP_list.append(acl_words[next_word_index] + "/" + str(netmask_to_cidr(acl_words[next_word_index + 1])))
			next_word_index = next_word_index + 2
			# CHANGED FROM 3 to 2 BECAUSE ERRORS IN NEXT GROUP 13-08-18_10-15
		else:
			print("|-->>> ERROR | no type found in word " + acl_words[next_word_index])
			print("|            | " + acl_line)


	#print(next_word_index)
	#print(acl_length)	
	if next_word_index < acl_length-1:
		# we can go further

		if acl_words[next_word_index] == 'object-group':
			og_name = acl_words[next_word_index+1]
			og_info = og_items.get(og_name, "NOT FOUND")
			og_original_line = og_info['original_og_row']
			og_type = og_info['og_type']

			if og_type == 'network':
				#this must be destination
				acl_destination_IP_list = get_og_items_flattened(parse, og_original_line, og_type)
				next_word_index = next_word_index + 2
			elif og_type == 'service':
				acl_destination_port_list = get_og_items_flattened(parse, og_original_line, og_type)
				next_word_index = next_word_index + 2
			else:
				print("|-->> ERROR | No OG network type when expected")
		elif acl_words[next_word_index] == 'object':
			o_name = acl_words[next_word_index+1]
			o_info = o_items.get(o_name, "NOT FOUND")
			o_original_line = o_info['original_o_row']
			#print("OBJECT FOUND : " + o_original_line + " BETA! CHECK CORRECT OUTPUT!!")
			new_item = get_object_item(parse, o_name, o_info['o_type'])
			acl_destination_IP_list.append(new_item)					
		else:
		#protocol list not empty, so protocols already known. Now we excpect source_subnet or 'host'
			if acl_words[next_word_index] == 'any' or acl_words[next_word_index] == 'any4' or acl_words[next_word_index] == 'any6':
				# one IP will follow from source host IP
				acl_destination_IP_list.append("0.0.0.0/0")
				next_word_index = next_word_index + 1
			elif acl_words[next_word_index] == 'eq':
				acl_destination_port_list.append(replace_port_name_to_number(acl_words[next_word_index+1]))
				next_word_index = next_word_index + 2
			elif acl_words[next_word_index] == 'range':

				og_dst_ports_start = int(replace_port_name_to_number(acl_words[next_word_index+1]))
				og_dst_ports_end = int(replace_port_name_to_number(acl_words[next_word_index+2]))
				if (EXTEND_PORT_RANGES):
					for i in range(og_dst_ports_start, og_dst_ports_end + 1):
						acl_destination_port_list.append(i)
				else:
					if len(acl_protocol_list) == 1:
						acl_destination_port_list.append(str(acl_protocol_list[0]) + ":" + str(og_dst_ports_start) + "-" + str(og_dst_ports_end))
					else:
						acl_destination_port_list.append(str(og_dst_ports_start) + "-" + str(og_dst_ports_end))
				next_word_index = next_word_index + 2	
			elif acl_words[next_word_index] == 'host':
				# one IP will follow from source host IP
				acl_destination_IP_list.append(acl_words[next_word_index+1] + "/32")
				next_word_index = next_word_index + 2
			elif is_ipv4(acl_words[next_word_index]) and is_ipv4(acl_words[next_word_index+ 1]):
				#we get source ip / sn
				acl_destination_IP_list.append(acl_words[next_word_index] + "/" + str(netmask_to_cidr(acl_words[next_word_index + 1])))
				next_word_index = next_word_index + 3
			elif acl_words[next_word_index] == 'log':
				# one IP will follow from source host IP
				acl_line_logged = True
				acl_line_logged_severity = acl_words[next_word_index+1]
			elif acl_words[next_word_index] == 'inactive':
				# one IP will follow from source host IP
				acl_line_inactive = True
			else:
				print("|-->> ERROR | no type found in word " + acl_words[next_word_index])
				print("|           | " + acl_line)
	

	# Create combined source or destination port list, combined with protocol
	

	#Validation
	#list_of_lists = [acl_type, acl_action, acl_source_IP_list, acl_action, acl_source_IP_list, acl_source_port_list, acl_destination_IP_list, acl_destination_port_list]
	#for idx, val in enumerate(list_of_lists):
	#	if val == '':
		#		print("|==>> ERROR | " + str(idx) + " not found")

	#if acl_protocol[0] == 'ip' and acl_destination_port_list == '':
	#	acl_destination_port_list = 'ip'
	protocol_to_dest_port = False
	if len(acl_source_port_list) == 0 and len(acl_destination_port_list) == 0 and len(acl_protocol_list) > 0:
		#Only protocols known like IP or ICMP, set this as destination port list
		#print("ONLY ACL PROTOCOLS ( "+ str(acl_protocol_list) +") KNOWN FOR " + acl_line)
		acl_destination_port_list = acl_protocol_list
		protocol_to_dest_port = True
	
	#Contruct protocol - port matches if only one protocol
	if len(acl_protocol_list) == 1 and len(acl_destination_port_list) >0:
		contructed_protocol_port_list = list()
		for port in acl_destination_port_list:
			contructed_protocol_port_list.append(str(acl_protocol_list[0]) + ":" + str(replace_port_name_to_number(port)).strip())
		#print(contructed_protocol_port_list)
		# NEw list:
		acl_destination_port_list = contructed_protocol_port_list
		# Empty protocol list
		acl_protocol_list = list()

	if (SHOW_SPLIT_LINE_OUTPUT):
		indent_space = 20
		print(" " * (indent_space-5) + "ACL LINE : " + str(acl_line))
		print(" " * indent_space + "source : " + str(acl_source_IP_list))
		print(" " * indent_space + "source port list :" + str(acl_source_port_list))
		print(" " * indent_space + "dest : " + str(acl_destination_IP_list))
		print(" " * indent_space + "protocol list : "+ str(acl_protocol_list))
		print(" " * indent_space + "dest port list : " + str(acl_destination_port_list))
		#print(" " * indent_space + " acl_protocol_list : " + str(acl_protocol_list))
		print(" " * indent_space + "Log enabled : " + str(acl_line_logged))
		print(" " * indent_space + "Log severity : " + str(acl_line_logged_severity))
		print(" " * indent_space + "ACL Inactive : " + str(acl_line_inactive))

	all_matches_list = [acl_source_IP_list, acl_destination_IP_list]
	if len(acl_protocol_list) >0 and protocol_to_dest_port == False:
		all_matches_list.append(acl_protocol_list)
		protocol_in_list = True
	else:
		protocol_in_list = False
	if len(acl_source_port_list) >0:
		all_matches_list.append(acl_source_port_list)
		source_ports_in_list = True
	else:
		all_matches_list.append(acl_destination_port_list)
		source_ports_in_list = False

	total_list = list(itertools.product(*all_matches_list))	
	
	if acl_line_number == 10091:
		pprint(total_list)

	return(total_list, acl_line_logged, acl_line_logged_severity, acl_line_inactive, source_ports_in_list, protocol_in_list, protocol_to_dest_port, acl_type, acl_action)

def encode_list_to_utf8(list_to_encode):
	if isinstance(list_to_encode, unicode):
		list_to_encode = map(str, list_to_encode)
		list_to_encode = [x.encode('ascii') for x in list_to_encode]
		return list_to_encode
	else:
		return list_to_encode

def get_og_items_flattened(parse, original_og_row, og_type):
	all_object_groups_items = list()
	
	try:
		og_items_children = iter(parse.find_all_children(original_og_row, exactmatch=True))
		next(og_items_children)
	except:
		no_og_items_found = True
		print("OBJECT-GROUP CONTENT : " + original_og_row + " NOT FOUND")
		print("|-->>> ERROR:  " + original_og_row + " not found for type " + og_type)


	for og_item_child in og_items_children:
		#print(og_item)		
		original_row_words = ''
		total_word_original_row = ''
		last_word_in_original_row = ''
		og_item_parts = ''
		new_item = ''
		og_dst_ports_start = ''
		og_dst_ports_end = ''

		og_item_words = og_item_child.split()
		if og_item_words[0] != 'group-object' and og_item_words[0] != 'description':
			#remove first part
			#new_item = og_item_child.strip()[len(og_type.lower() + "-object "):] 
			og_item_parts = og_item_child.strip().split()
			
			# If type = service, possibile split and loop trough items as tcp-udp, range etc.
			if og_type.lower() == 'service':
				#og_item_parts = new_item
				if len(og_item_parts) > 1:
					if og_item_parts[0] == 'service-object':
						if og_item_parts[1] == 'eq':
							# One item to return
							new_item = og_item_parts[1] + ":" + replace_port_name_to_number(og_item_parts[2])
							all_object_groups_items.append(new_item)
						elif og_item_parts[1] == 'range':
							# Find all ports in range

							og_dst_ports_start = int(replace_port_name_to_number(og_item_parts[2]))
							og_dst_ports_end = int(replace_port_name_to_number(og_item_parts[3]))
							if (EXTEND_PORT_RANGES):
								for i in range(og_dst_ports_start, og_dst_ports_end + 1):
									new_item = og_item_parts[1] + ":" + replace_port_name_to_number(str(i))
									all_object_groups_items.append(new_item)
							else:
								all_object_groups_items.append(og_item_parts[1] + ":" + str(og_dst_ports_start) + "-" + str(og_dst_ports_end))
						elif og_item_parts[1] == 'icmp':
							if len(og_item_parts) > 2:
								new_item = og_item_parts[1] + ":" + og_item_parts[2]
							else:
								new_item = og_item_parts[1]
							all_object_groups_items.append(new_item)
					elif og_item_parts[0] == 'port-object':
						#Get protocol (last word of original_row) 
						original_row_words = original_og_row.split()
						total_word_original_row = len(original_row_words)
						port_object_protocol = original_row_words[total_word_original_row-1]

						if og_item_parts[1] == 'eq':
							# One item to return
							#new_item = port_object_protocol + ":" + replace_port_name_to_number(og_item_parts[2])
							new_item = replace_port_name_to_number(og_item_parts[2])
							all_object_groups_items.append(new_item)
						elif og_item_parts[1] == 'range':
							# Find all ports in range
							#print(og_item_child)
							#print("PORT RANGE IN " + original_og_row)
							og_dst_ports_start = int(replace_port_name_to_number(og_item_parts[2]))
							og_dst_ports_end = int(replace_port_name_to_number(og_item_parts[3]))
							if (EXTEND_PORT_RANGES):
								for i in range(og_dst_ports_start, og_dst_ports_end + 1):
									#new_item = port_object_protocol + ":" + replace_port_name_to_number(str(i))
									new_item = replace_port_name_to_number(str(i))
									all_object_groups_items.append(new_item)
							else:
								#all_object_groups_items.append(port_object_protocol + ":" + str(og_dst_ports_start) + "-" + str(og_dst_ports_end))
								all_object_groups_items.append(str(og_dst_ports_start) + "-" + str(og_dst_ports_end))

				else:
					all_object_groups_items.append(og_item_child.strip())
			elif og_type.lower() == 'network':
				#print(og_item_parts)
				if len(og_item_parts) > 1:
					if og_item_parts[1] == 'host':
						new_item = og_item_parts[2] + "/32"
						all_object_groups_items.append(new_item)

					elif og_item_parts[1] == 'object':
						#research OGs - NEW FUCTION ADD
						#print("OBJECT FOUND : " + original_og_row + " BETA! CHECK CORRECT OUTPUT!!")
						new_item = get_object_item(parse, og_item_parts[2], og_type)
						all_object_groups_items.append(new_item)
					else:
						if is_ipv4(og_item_parts[1]) and is_ipv4(og_item_parts[2]):
							new_item = og_item_parts[1] + "/" + str(netmask_to_cidr(og_item_parts[2]))
							all_object_groups_items.append(new_item)

						else:
							print("|-->>> ERROR | Cannot extract network group object to CIDR")
							print("|            | " + original_og_row)
			elif og_type.lower() == 'protocol':
				#print("PROTOCOL" + og_item_child.strip() + " " + original_og_row + " ( " + og_type + " )")
				og_item_parts = og_item_child.strip().split()
				#second word is protocol
				all_object_groups_items.append(og_item_parts[1])
			else:
				print("NOT MATCH -> JUST ADDED")
				all_object_groups_items.append(og_item_child.strip())
		elif og_item_words[0] == 'group-object':
			#next_group = extract_nested_object_groups(parse, og_type, og_item_words[1])
			# Get orgininal line
			og_name = og_item_words[1]
			og_info = og_items.get(og_name, "NOT FOUND")
			og_original_line = og_info['original_og_row']
			og_type = og_info['og_type']
			#print(og_original_line)
			all_object_groups_items.append(get_og_items_flattened(parse, og_original_line, og_type))

	all_object_groups_items = flatten(all_object_groups_items)
	
	#print("Voor flatten og_items: ")
	#print(all_object_groups_items)

	return all_object_groups_items


def get_object_item(parse, object_name, og_type):
	#Function to get ONE OBJECT
	# description can be first or second line!
	object_row = 'object ' + og_type + ' ' + object_name
	o_items_children = iter(parse.find_all_children(object_row, exactmatch=True))
	next(o_items_children)
	for o_line in o_items_children:
		o_line_words = o_line.split()
		if o_line_words[0] == 'host':
			#return host IP in CIDR
			return o_line_words[1] + "/32"
		elif o_line_words[0] == 'range':
			#return host IP in CIDR
			range_list = list()
			if og_type == 'network':
				#List of IP addresses
				ip_list = IPSet(IPRange(o_line_words[1], o_line_words[2]))

				for ip in ip_list:
					range_list.append(str(ip) + "/32")
				return range_list
		elif o_line_words[0] == 'subnet':
			#return subnet in CIDR
			host_ip = o_line_words[1]
			host_sn = o_line_words[2]
			host_cidr = host_ip + "/" + str(netmask_to_cidr(host_sn))
			return host_cidr
		else:
			print("No object type handler found for |" + o_line_words[0] + "| - " +  object_row + " - " + o_line)

	

def export_dict_to_csv(extracted_acl_lines):
	if python3 == True:
		open_csv_writemode = 'w'
	else:
		open_csv_writemode = 'wb'

	export_dir = os.path.join(output_dir, '')
	export_file = hostname + '-all_acl_lines.csv'
	#Delete file if exist
	if not os.path.exists(export_dir):
		os.makedirs(export_dir)
	else:
		#Folder exist, remove file if already exist
		try:
			os.remove(export_dir + export_file)
		except OSError:
			pass

	extracted_acl_lines.to_csv(export_dir + export_file, encoding='utf-8')


def get_acl_line_word(acl_line, word_nr):
	acl_words = acl_line.split()
	return acl_words[word_nr-1]

def replace_port_name_to_number(name):
	# Note portDict is read in Globally from CSV file!
	# This returns input back if no match found
	portNumber = re.sub(r'\b'+name+r'\b', lambda m: portDict.get(m.group(), m.group()), name)    	
	#portNumber = re.sub(r'\b'+name+r'\b', lambda m: portDict.get(m.group()), name)					# This returns nothing when not found in dict
	return portNumber

def find_IP_in_range(start, end):
	# Need ipaddress or ipaddr library
	start = ip_address(start)
	end = ip_address(end)
	result = []
	while start <= end:
		result.append(str(start))
		start += 1
	return result

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

def get_hostname(parse):
	hostname_row = parse.find_lines(r'^hostname ')
	hostname_row = hostname_row[0]
	hostname = hostname_row.strip()[len("hostname "):] 
	return hostname

def get_nameif_interfaces(parse):
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

def extract_asa_config_file(parse):


	#Get hostname - needed for printout and export
	global hostname
	hostname = ''
	hostname = get_hostname(parse)

	# Only READ IN ONCE! = Global, Reverced = True
	# Need import of __routing__.py
	global network_routes	
	network_routes = dict()
	network_routes = get_network_routes(parse, True)

	# Create global dict with all acl lines
	global extracted_acl_lines
	extracted_acl_lines = dict()

	# Create global dict with portname to number, only if enabled for extraction
	global portDict
	portDict = dict()
	if EXPORT_CHANGE_PORT_TO_NUMBER == True:

		portDict_CSV = './external/cisco_asa_pname-pnum.csv'
		with open(portDict_CSV, mode='r') as portDict_CSV_file:
			reader = csv.reader(portDict_CSV_file)
			for row in reader:
				#pprint(row)
				portDict[row[0]] = row[1]		

	# Get insterfaces
	all_intfs = intf_acl_to_dict(parse)
	total_acl_lines = 0
	#Loop trough interfaces and return extracted ACL lines
	for key, value in all_intfs.items():
		print(key, value)
		
		## START ACL_IN EXTRACTION
		parsed_remark_lines = 0
		parsed_acl_lines = 0
		parsed_unknown_lines = 0
		
		print("")
		print("******" + hostname + "******")
		print("ACL extraction for " + str(key))

		acl_interface = key
		acl_nameif = str(value[u'nameif'])
		acl_direction = 'incoming'
		acl_name = str(value[u'acl_in'])
		
		#Dict for checking all ACL lines are processed:
		processed_acl_lines = dict()

		if  acl_name != '' and acl_name != 'None':
			total_acl_lines, parsed_remark_lines, parsed_acl_lines, parsed_unknown_lines, acl_lines_this_acl,  processed_acl_lines = get_acl_lines(parse, total_acl_lines, acl_name, acl_interface, acl_direction)
			#add new lines to global dict
			extracted_acl_lines.update(acl_lines_this_acl)
			#pprint(acl_lines_this_acl)
			for key, value in processed_acl_lines.items():
				if value['acl_processed'] == False and value['acl_type'] != 'remark':
					pprint(value)
		total_acl_lines = total_acl_lines + total_acl_lines
		print("*" * 40)
		print(" This ACL Remarks :" + str(parsed_remark_lines))
		print(" This ACL lines : " + str(parsed_acl_lines))
		print(" This ACL Unknown lines : " + str(parsed_unknown_lines))
		print("*" * 40)
		print(" Total ACL Lines :" + str(total_acl_lines))
		print("*" * 80)

	# Create pandas DataFram from total dict
	extracted_acl_lines = pd.DataFrame.from_dict(extracted_acl_lines, orient='index')
	

	#Export returning DICT
	if EXPORT_TO_CSV == True:

		csv_output = export_dict_to_csv(extracted_acl_lines)
		print(csv_output)
	else:
		print(extracted_acl_lines)


def read_config_files(input_dir):
	config_files = dict()
	file_counter = 0
	# This is the path where you want to search
	path = input_dir
	# this is the extension you want to detect
	#extension = '.confg'
	extension = ''
	for root, dirs_list, files_list in os.walk(path):
		for file_name in files_list:
			if os.path.splitext(file_name)[-1] == extension:
				file_counter += 1
				file_name_path = os.path.join(root, file_name)
				print(file_name)
				print(file_name_path)   # This is the full path of the filter file
				new_dict_line = {'file_name': file_name, 'file_path': file_name_path}
				config_files[file_counter] = new_dict_line
	return config_files

def main():
	
	# Get al ACL_input files
	config_files = dict()
	config_files = read_config_files(input_dir)
	#print(config_files)
	
	# Loop trough config_files
	for key, value in config_files.items():
		# Read in config
		print("Read config file : " + str(value[u'file_name']))
		parse = parseconfig(value[u'file_path'])
		pprint(parse)	
		extraction = extract_asa_config_file(parse)
			
	

	#print("ALL ACL LINE DICT!!:")
	#pprint(extracted_acl_lines)

if __name__ == "__main__":
	main()