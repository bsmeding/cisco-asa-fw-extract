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
#import six						# Check Python 2 and 3 for type string # six module not installed by default

# Import ipaddress library based on Python version (2.x of 3.2 = ipaddr >3.2 ipaddres) used to calculate ip addresses in range
try:
    from ipaddress import ip_address
except ImportError:
    from ipaddr import IPAddress as ip_address

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
EXPORT_TO_CSV = True 			# Export ACL Lines to CSV. Default: True
EXPORT_REMARKS = False 			# Skip the remark lines in export output. Default: False
EXPORT_ORIGINAL_LINE = True 	# Export the original ACL line (takes longer, and more export data). Default: True
FLATTEN_NESTED_LISTS = True		# True if the output of nested lists must be extracted to one list   << AFTER CHANGING TO DICTS THIS IS NOT WORKING ANYMORE !!!!!! CHECK. Default: True
SKIP_INACTIVE = True			# True to skip lines for printing that are inactive (last word of ACL line). Default: True
EXTEND_PORT_RANGES = True 		# When True the ranges will be added seperataly, from begin to end range port. Other it will be printed as <port_start>-<port_end>   << NEEDS TO BE CHECKED. Default: True
CALCULATE_NEXT_HOP_INFO = True 	# Calculate next hop interface, ip and route prio. Note that this will need some time as it will calculate for each row!. Default: False
EXPORT_CHANGE_PORT_TO_NUMBER = True 	# Default: True
SKIP_TIME_EXCEEDED = False		# Skip rules with time-ranges that have passed by NOT IMPLEMENTED YET!!. Default: False
CREATE_DICT = True 				# Maybe remove! Default: True
SHOW_SPLIT_LINE_OUTPUT = True
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
	create_og_dict(parse)


	# Create ympty Dictionary for export
	acl_line_dict = dict()
	


	#pprint(og_items)
	
	for acl_line in parse.find_objects(r'access-list\s'):
		
		if acl_name in acl_line.text:
			total_acl_lines += 1
			acl_line_number = acl_line.linenum
			acl_line = acl_line.text.split(' ', 2)[2]
			
			# First check if remark or ACL type
			if acl_line.partition(' ')[0] == 'remark':
				parsed_remark_lines = parsed_remark_lines + 1
				if (PRINT_REMARKS == True and PRINT_LINES == True) or (debug):
					print(acl_line_number), ":",
					print(acl_line)
				if EXPORT_REMARKS == True:
					# Go further and split ACL
					new_acl_dict_line = split_acl_lines(parse, acl_line, total_acl_lines, acl_line_number, acl_line_dict)
					acl_line_dict[total_acl_lines] = new_acl_dict_line

					#Update cells with global acl information (columes alreaddy exported empty by function split_acl_lines)
					acl_line_dict[total_acl_lines].update({'acl_interface': acl_interface})
					acl_line_dict[total_acl_lines].update({'acl_direction': acl_direction})
					acl_line_dict[total_acl_lines].update({'acl_name': acl_name})
					# Add original row
					if EXPORT_ORIGINAL_LINE == True:
						acl_line_dict[total_acl_lines].update({'original_acl_line': acl_line})
					if (debug):
						print("NEW ACL LINE TO DICT : "),
						pprint(acl_line_dict[total_acl_lines])

							
					
			elif acl_line.partition(' ')[0] == 'extended':

				parsed_acl_lines = parsed_acl_lines + 1	

				split_acl_line(parse, acl_line, acl_line_number, acl_line_dict)
				


			else:
				parsed_unknown_lines = parsed_unknown_lines + 1
				print("ERROR! Unkown ACL type!")

	# OLD DIRECT EXPORT TO CSV FILE
	#export_dict_to_csv_old(acl_line_dict, acl_name)

	return (total_acl_lines, parsed_remark_lines, parsed_acl_lines, parsed_unknown_lines, acl_line_dict)

def split_acl_line(parse, acl_line, acl_line_number, dict_to_update):
	# Create empty variables for return
	acl_type = ''
	acl_action = ''
	#acl_protocol_list = ''
	acl_protocol = ''
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
	if acl_words[2] != 'object-group':
		# protocol is known for all next ports
		acl_protocol = acl_words[2]
		next_word_index = 3
	else:
		#protocol is in object-group 
		# can also been source network
		#print("protocol in object-group or source network")
		og_name = acl_words[3]
		og_info = og_items.get(og_name, "NOT FOUND")
		og_original_line = og_info['original_og_row']
		next_og_source_og = False
		if og_info['og_type'] == 'network':
			print("NETWORK OG")
			next_og_source_IP_og = False 		# Next OG cannot be an source IP network
			acl_destination_port_list = get_og_items_flattened(parse, og_original_line, og_info['og_type'])
		else:
			next_og_source_IP_og = True 		# Next OG must be source OG as we alreade have protocol type OG
			acl_destination_port_list = get_og_items_flattened(parse, og_original_line, og_info['og_type'])
		next_word_index = 4

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
				print("|-->> ERROR | No OG network type when expected")
		else:
			#this will be source port OG, or destinaG
			print("uitzoeken source PORT OG of DEST IP OG")
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
			print("|-->> ERROR | no type found in word " + acl_words[next_word_index])
	
	

	#print(acl_words[next_word_index])

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
	else:
	#protocol list not empty, so protocols already known. Now we excpect source_subnet or 'host'
		if acl_words[next_word_index] == 'any' or acl_words[next_word_index] == 'any4' or acl_words[next_word_index] == 'any6':
			# one IP will follow from source host IP
			acl_destination_IP_list.append("0.0.0.0/0")
			next_word_index = next_word_index + 1
		elif acl_words[next_word_index] == 'eq':
			# Source ports are used
			acl_source_port_list = [acl_protocol +":" + acl_words[next_word_index+1]]
			#print("source protocols : " + str(acl_protocol_list))
			acl_have_source_protocols = True
			next_word_index = next_word_index + 2
		elif acl_words[next_word_index] == 'host':
			# one IP will follow from source host IP
			acl_destination_IP_list.append(acl_words[next_word_index+1] + "/32")
			next_word_index = next_word_index + 2
		elif is_ipv4(acl_words[next_word_index]) and is_ipv4(acl_words[next_word_index+ 1]):
			#we get source ip / sn
			acl_destination_IP_list.append(acl_words[next_word_index] + "/" + str(netmask_to_cidr(acl_words[next_word_index + 1])))
			next_word_index = next_word_index + 3
		else:
			print("|-->> ERROR | no type found in word " + acl_words[next_word_index])


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
		else:
		#protocol list not empty, so protocols already known. Now we excpect source_subnet or 'host'
			if acl_words[next_word_index] == 'any' or acl_words[next_word_index] == 'any4' or acl_words[next_word_index] == 'any6':
				# one IP will follow from source host IP
				acl_destination_IP_list.append("0.0.0.0/0")
				next_word_index = next_word_index + 1
			elif acl_words[next_word_index] == 'eq':
				acl_destination_port_list = [acl_protocol +":" + acl_words[next_word_index+1]]
				next_word_index = next_word_index + 2
			elif acl_words[next_word_index] == 'range':
				og_dst_ports_start = int(replace_port_name_to_number(acl_words[next_word_index+1]))
				og_dst_ports_end = int(replace_port_name_to_number(acl_words[next_word_index+2]))

				for i in range(og_dst_ports_start, og_dst_ports_end):
					acl_destination_port_list.append(i)
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
	#Validation
	#list_of_lists = [acl_type, acl_action, acl_source_IP_list, acl_action, acl_source_IP_list, acl_source_port_list, acl_destination_IP_list, acl_destination_port_list]
	#for idx, val in enumerate(list_of_lists):
	#	if val == '':
		#		print("|==>> ERROR | " + str(idx) + " not found")

	if acl_protocol == 'ip' and acl_destination_port_list == '':
		acl_destination_port_list = 'ip'


	# Encode Unicode strings in listst to UTF-8
	#acl_source_IP_list = encode_list_to_utf8(acl_source_IP_list)
	#acl_source_port_list = encode_list_to_utf8(acl_source_port_list)
	#acl_destination_IP_list = encode_list_to_utf8(acl_destination_IP_list)
	#acl_destination_port_list = encode_list_to_utf8(acl_destination_port_list)
	#acl_destination_port_list  = [x.encode('utf-8') for x in acl_destination_port_list]
	#print("ACL SRC IP", type(acl_source_IP_list))
	#print("ACL SRC PRT", type(acl_source_port_list))
	#print("ACL DST IP", type(acl_destination_IP_list))
	#print("ACL DST PRT",  type(acl_destination_IP_list))
	
	if (SHOW_SPLIT_LINE_OUTPUT):
		indent_space = 20

		print(" " * indent_space + " source : " + str(acl_source_IP_list))
		print(" " * indent_space + " source port list :" + str(acl_source_port_list))
		print(" " * indent_space + " dest : " + str(acl_destination_IP_list))
		print(" " * indent_space + " dest port list : " + str(acl_destination_port_list))
		#print(" " * indent_space + " acl_protocol_list : " + str(acl_protocol_list))
		print(" " * indent_space + " Log enabled : " + str(acl_line_logged))
		print(" " * indent_space + " Log severity : " + str(acl_line_logged_severity))
		print(" " * indent_space + " ACL Inactive : " + str(acl_line_inactive))

		acl_source_destination_port_list = list(itertools.product(acl_destination_IP_list, acl_destination_port_list))
				
		print(acl_source_destination_port_list)
	return(acl_protocol, acl_source_IP_list, acl_source_port_list, acl_destination_IP_list, acl_destination_port_list, acl_line_logged, acl_line_logged_severity, acl_line_inactive)

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
		og_item_words = og_item_child.split()
		if og_item_words[0] != 'group-object' and og_item_words[0] != 'description':
			#remove first part
			new_item = og_item_child.strip()[len(og_type.lower() + "-object "):] 
			new_item = new_item.strip()
			# If type = service, possibile split and loop trough items as tcp-udp, range etc.
			if og_type.lower() == 'service':
				og_item_parts = new_item.split()
				if len(og_item_parts) > 1:
#					print(og_item_parts)
					if og_item_parts[1] == 'eq':
						# One item to return
						new_item = og_item_parts[0] + ":" + og_item_parts[2]
						all_object_groups_items.append(new_item)
					elif og_item_parts[1] == 'range':
						# Find all ports in range
						og_dst_ports_start = int(replace_port_name_to_number(og_item_parts[2]))
						og_dst_ports_end = int(replace_port_name_to_number(og_item_parts[3]))

						for i in range(og_dst_ports_start, og_dst_ports_end):
							#acl_range_ports.append(get_acl_line_word(acl_line, i).encode("ascii"))
							new_item = og_item_parts[0] + ":" + str(i)
							all_object_groups_items.append(new_item)
				else:
					all_object_groups_items.append(new_item)
			elif og_type.lower() == 'network':
				og_item_parts = new_item.split()
				#print(og_item_parts)
				if len(og_item_parts) > 1:
					if og_item_parts[0] == 'host':
						new_item = og_item_parts[1] + "/32"
						all_object_groups_items.append(new_item)
					else:
						if is_ipv4(og_item_parts[0]) and is_ipv4(og_item_parts[1]):
							new_item = og_item_parts[0] + "/" + str(netmask_to_cidr(og_item_parts[1]))
							all_object_groups_items.append(new_item)

						else:
							print("|-->>> ERROR | Cannot extract network group object to CIDR")
			elif og_type.lower() == 'protocol':
				#print(new_item)
				all_object_groups_items.append(new_item)
			else:
				print("NOT MATCH -> JUST ADDED")
				all_object_groups_items.append(new_item)
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

def export_dict_to_csv(extracted_acl_lines):
	"""
	This function will export the returning ACL Lines (in dict) to CSV file. There are two options to export, 
	in original one liner with object-groups or with extracted object-groups (one line per protocol, destination address and port)
	"""
	# Export Dictionary to CSV
	if extracted_acl_lines != '':

		if python3 == True:
			open_csv_writemode = 'w'
		else:
			open_csv_writemode = 'wb'
			

		# Create one file with all ACLs
		csv_columns = ['acl_line_number', 'acl_line_child', 'acl_interface', 'acl_direction', 'acl_name', \
				'inactive', 'acl_type', 'acl_action', \
				'acl_source_host_id', 'acl_source_host_sn', 'acl_source_port', 'acl_dst_host_id', 'acl_dst_host_sn', 'acl_dst_port', 'acl_protocol', \
				'dst_interface', 'dst_next_hop', 'dst_next_hop_prio', \
				'original_acl_line']

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

		#add new export
		with open(export_dir + export_file, open_csv_writemode) as csv_file:
			writer = csv.writer(csv_file)
			writer.writerow(csv_columns)
			for key, item in extracted_acl_lines.items():
				acl_line_child = 0
				#Create row
				#Chech for simple line, without object-groups
				acl_protocol_row = '' 
				source_ips = ''
				acl_source_port = item[u'acl_source_port']
				destination_ips = ''
				acl_protocol_items = ''
				destination_ports = ''
				if item[u'acl_type'] != 'remark':
					# Create protocol list
					if item[u'acl_protocol_og_list'] != '':
						#loop trough OG list
						acl_protocol_items = item[u'acl_protocol_og_list']
						if (debug):
							print("Ports in protocol OG : "), acl_protocol_items					

					else:
						# Set ACL_protocol to protocol item, needed in destination_ports loop ???(CHECK)
						acl_protocol = str(item[u'acl_protocol'])
					


					# Create source IP list
					if item[u'acl_source_og_list'] != '':
						#loop trough OG list
						source_ips = item[u'acl_source_og_list']
					else:
						source_ips = [item[u'acl_source_sn'] + ' ' + item[u'acl_source_nm']]
					# Create Destination IP list
					if item[u'acl_dst_og_list'] != '':
						#loop trough OG list
						destination_ips = item[u'acl_dst_og_list']
				
					else:
						destination_ips = [item[u'acl_dst_sn'] + ' ' + item[u'acl_dst_nm']]

					# Create Destination port list					

					if item[u'acl_dst_ports_og_items_list'] != '':
						if (debug):
							print("Dest ports in OG")
						destination_ports = item[u'acl_dst_ports_og_items_list']
					#elif item[u'acl_dst_ports_og_items_list'] != '':
					#	destination_ports = item[u'acl_dst_ports_og_items_list']
					else:
						destination_ports =  [item[u'acl_dst_ports']]


					if (debug):
						print("Source IP in OG : "), source_ips	
						print("Destination IP's "), destination_ips			
						print("Protocol ports "), acl_protocol_items
						print("Destination ports"), destination_ports

					# 10-8-18 Also do this for OG when OG in source ports is used!! 	
					if item[u'acl_protocol_og_list'] != '':
						#acl_source_destination_port_list = list(itertools.product(source_ips, destination_ips, destination_ports, acl_protocol_items))	
						acl_source_destination_port_list = list(itertools.product(source_ips, destination_ips, acl_protocol_items))	
					else:
						acl_source_destination_port_list = list(itertools.product(source_ips, destination_ips, destination_ports))	
					
					if (debug):
						print("ACL Source - Destination - Portlist")
						pprint(acl_source_destination_port_list )
						print("")
					# LOOP trough items
					for list_item in acl_source_destination_port_list:
						acl_line_child = acl_line_child + 1
						#split into 4 parts, source, destination, port, protocol. 
						#print(list_item[0], list_item[1], list_item[2])
						acl_source_host_id = ''
						acl_source_host_sn = ''
						acl_dst_host_id = ''
						acl_dst_host_sn = ''
						acl_dst_port = ''
						acl_dst_port_number = ''
						acl_protocol = ''
						acl_source_full = list_item[0].split()
						acl_source_host_id = acl_source_full[0]
						if len(acl_source_full) >1:
							acl_source_host_sn = acl_source_full[1]	
						acl_dst_full = list_item[1].split()
						acl_dst_host_id = acl_dst_full[0]
						if len(acl_dst_full) >1:				# 31-5 changed added [1]
							acl_dst_host_sn = acl_dst_full[1]	
						acl_dst_port = list_item[2]
						if item[u'acl_protocol_og_list'] != '':
							acl_protocol_full = list_item[2].split()
							if len(acl_protocol_full) >1:
								acl_protocol = acl_protocol_full[0]
								acl_dst_port = acl_protocol_full[1]
							else:
								acl_protocol = list_item[2]
								acl_dst_port = ''
						else:
							acl_protocol = item[u'acl_protocol']

						# Calculate next hop and outgoing interface based on destination CIDR
						dst_next_hop_intf = ''
						dst_next_hop_ip = ''
						dst_next_hop_prio = ''
						if is_obj_int(acl_dst_host_sn):
							acl_dst_cidr = acl_dst_host_id + "/" + str(netmask_to_cidr(acl_dst_host_sn))
						else:
							acl_dst_cidr = acl_dst_host_id + "/" + acl_dst_host_sn
						#except:
						#	print("|-->>> ERROR: CIDR calculation line : " + str(item[u'acl_line_number']) + " for acl_dst_host_id: " + acl_dst_host_id + " acl_dst_host_sn: " + acl_dst_host_sn)
						#	pass
						if CALCULATE_NEXT_HOP_INFO == True:
							try:
								dst_next_hop_info = get_ip_next_hop(network_routes, acl_dst_cidr)
								if (debug):
									print("ACL NEXT HOP INFO. Host " + acl_dst_host_id + " - SN:" +  acl_dst_host_sn + " CIDR " + acl_dst_cidr), 
									print(dst_next_hop_info)
								
								dst_next_hop_ip = dst_next_hop_info[0]
								dst_next_hop_intf = dst_next_hop_info[1]
								dst_next_hop_prio = dst_next_hop_info[2]
							except:
								pass

						# OPTIONAL CHANGE PORT NAME TO NUMBER

						if EXPORT_CHANGE_PORT_TO_NUMBER == True and is_obj_string(acl_dst_port) == True:
							
							#print("Change port to number : " + acl_dst_port)
							acl_dst_port_number = replace_port_name_to_number(acl_dst_port)
							acl_source_port_number = replace_port_name_to_number(acl_source_port)
							#print("   CHANGED TO : " + acl_dst_port_number)
						else:
							acl_dst_port_number = type(acl_dst_port)
							acl_source_port_number = acl_source_port

						new_csv_row = (int(item[u'acl_line_number']), acl_line_child, item[u'acl_interface'], item[u'acl_direction'], item[u'acl_name'], \
							item[u'inactive'], item[u'acl_type'], item[u'acl_action'], \
							acl_source_host_id, acl_source_host_sn, acl_source_port_number, acl_dst_host_id, acl_dst_host_sn, acl_dst_port_number, acl_protocol,\
							dst_next_hop_intf, dst_next_hop_ip, dst_next_hop_prio, \
							item[u'original_acl_line'])
						if (debug):
							print("NEW DICT TO CSV LINE: "),
							print(new_csv_row)
						writer.writerow(new_csv_row)

					#print(new_csv_row)
					#writer.writerow(new_csv_row)
				else: # = remark
					new_csv_row = (int(item[u'acl_line_number']), acl_line_child, item[u'acl_interface'], item[u'acl_direction'], item[u'acl_name'], \
						item[u'inactive'], item[u'acl_type'], '', \
							'' , '', '', '', '', '', \
							item[u'original_acl_line'])
					writer.writerow(new_csv_row)

			






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

		if  acl_name != '' and acl_name != 'None':
			total_acl_lines, parsed_remark_lines, parsed_acl_lines, parsed_unknown_lines, acl_lines_this_acl = get_acl_lines(parse, total_acl_lines, acl_name, acl_interface, acl_direction)
			#add new lines to global dict
			extracted_acl_lines.update(acl_lines_this_acl)
			#pprint(acl_lines_this_acl)
		total_acl_lines = total_acl_lines + total_acl_lines
		print("*" * 40)
		print(" This ACL Remarks :" + str(parsed_remark_lines))
		print(" This ACL lines : " + str(parsed_acl_lines))
		print(" This ACL Unknown lines : " + str(parsed_unknown_lines))
		print("*" * 40)
		print(" Total ACL Lines :" + str(total_acl_lines))
		print("*" * 80)

	#Export returning DICT
	if EXPORT_TO_CSV == True:
		csv_output = export_dict_to_csv(extracted_acl_lines)
		print(csv_output)


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