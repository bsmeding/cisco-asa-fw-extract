#!/usr/bin/env python
from __future__ import unicode_literals

import os
import sys
import re
import itertools							# To combine list and all permutations
#import getpass
#import time
#import ___ipaddress___						# IPaddress validation
#import ___cidr_convert___					# Convert CIDR to Network address and reverse

from __routing__ import *
from pprint import pprint
from ciscoconfparse import CiscoConfParse
#from ciscoconfparse.ccp_util import IPv4Obj
#from collections import namedtuple
#import cidr_convert
import csv 						# CSV Export 
import shutil								# Needed for deleting export files in folder


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


PRINT_REMARKS = False			# True for print to screen, False no print to screen
PRINT_LINES = False 			# Print line info
PRINT_FULL_OUTPUT = False 		# Print full extract info (debug)
EXPORT_TO_CSV = True 			# Export ACL Lines to CSV
EXPORT_REMARKS = False 			# Skip the remark lines in export output
EXPORT_ORIGINAL_LINE = True 	# Export the original ACL line (takes longer, and more export data)
FLATTEN_NESTED_LISTS = True		# True if the output of nested lists must be extracted to one list   << AFTER CHANGING TO DICTS THIS IS NOT WORKING ANYMORE !!!!!! CHECK
SKIP_INACTIVE = True			# True to skip lines that are inactie (last word of ACL line)
EXTEND_PORT_RANGES = True 		# When True the ranges will be added seperataly, from begin to end range port. Other it will be printed as <port_start>-<port_end>   << NEEDS TO BE CHECKED


SKIP_TIME_EXCEEDED = False		# Skip rules with time-ranges that have passed by
debug = False
CREATE_DICT = True 				# Maybe remove!
#EXPORT_ACL_SEPERATE_FILES = False 	# Export each ACL to separate file

#input_config_file = "confsmall.conf" 
input_config_file = "ciscoconfig.conf" 
output_csv_file = "acl_seperated.csv"
output_dir = 'output'

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
	# - No Service-Group names in output
	#
	# ToDo Validation
"""



# Create output directory
output_dir = './' + output_dir



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

def get_acl_lines(parse, total_acl_lines, acl_name, acl_interface, acl_direction):
	"""
	Get ACL line by line and parse to split_acl_lines to analyse per word

	"""

	parsed_remark_lines = 0
	parsed_acl_lines = 0
	parsed_unknown_lines = 0

	# Get variables per ACL
	#acl_interface = acl_interface
	#acl_nameif = acl_nameif
	#acl_direction = acl_direction
	#acl_name = acl_name

	# Create ympty Dictionary for export
	acl_line_dict = dict()

	for acl_line in parse.find_objects(r'access-list\s'):
		
		if acl_name in acl_line.text:
			total_acl_lines = total_acl_lines + 1
			acl_line_number = acl_line.linenum
			acl_line = acl_line.text.split(' ', 2)[2]
			
			# First check if remark or ACL type
			if acl_line.partition(' ')[0] == 'remark':
				parsed_remark_lines = parsed_remark_lines + 1
				if PRINT_REMARKS == True and PRINT_LINES == True:
					print(acl_line_number), ":",
					print(acl_line)
				if EXPORT_REMARKS == True:
					# Go further and split ACL
					new_acl_dict_line = split_acl_lines(parse, acl_line, total_acl_lines, acl_line_number)
					acl_line_dict[total_acl_lines] = new_acl_dict_line

					#Update cells with global acl information (columes alreaddy exported empty by function split_acl_lines)
					acl_line_dict[total_acl_lines].update({'acl_interface': acl_interface})
					acl_line_dict[total_acl_lines].update({'acl_direction': acl_direction})
					acl_line_dict[total_acl_lines].update({'acl_name': acl_name})

					# Add original row
					if EXPORT_ORIGINAL_LINE == True:
						acl_line_dict[total_acl_lines].update({'original_acl_line': acl_line})

							
					
			elif acl_line.partition(' ')[0] == 'extended':
				parsed_acl_lines = parsed_acl_lines + 1	
				new_acl_dict_line = split_acl_lines(parse, acl_line, total_acl_lines, acl_line_number)
				acl_line_dict[total_acl_lines] = new_acl_dict_line

				#Update cells with global acl information (columes alreaddy exported empty by function split_acl_lines)
				acl_line_dict[total_acl_lines].update({'acl_interface': acl_interface})
				acl_line_dict[total_acl_lines].update({'acl_direction': acl_direction})
				acl_line_dict[total_acl_lines].update({'acl_name': acl_name})

				# Add original row
				if EXPORT_ORIGINAL_LINE == True:
					acl_line_dict[total_acl_lines].update({'original_acl_line': acl_line})
			else:
				parsed_unknown_lines = parsed_unknown_lines + 1
				print("ERROR! Unkown ACL type!")

	# OLD DIRECT EXPORT TO CSV FILE
	#export_dict_to_csv_old(acl_line_dict, acl_name)

	return (total_acl_lines, parsed_remark_lines, parsed_acl_lines, parsed_unknown_lines, acl_line_dict)

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
				'acl_protocol_og', 'acl_protocol_og_list', \
				'acl_source_host_id', 'acl_source_host_sn', 'acl_dst_host_id', 'acl_dst_host_sn', 'acl_dst_port', 'acl_protocol', \
				'original_acl_line']

		export_dir = os.path.join(output_dir, '')
		#Clear folder
		shutil.rmtree(export_dir, ignore_errors=True)
		if not os.path.exists(export_dir):
			os.makedirs(export_dir)
		#add new export
		with open(export_dir + 'all_acl_lines.csv', open_csv_writemode) as csv_file:
			writer = csv.writer(csv_file)
			writer.writerow(csv_columns)
			for key, item in extracted_acl_lines.items():
				acl_line_child = 0
				#Create row
				#Chech for simple line, without object-groups
				acl_protocol_row = '' 

				if item[u'acl_type'] != 'remark':
					# Create protocol list
					if item[u'acl_protocol_og_list'] != '':
						#loop trough OG list
						acl_protocol_items = item[u'acl_protocol_og_list']

					else:
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
						destination_ports = item[u'acl_dst_ports_og_items_list']
					elif item[u'acl_dst_ports_og_items_list'] != '':
						destination_ports = item[u'acl_dst_ports_og_items_list']
					else:
						destination_ports =  [item[u'acl_dst_ports']]


					if item[u'acl_source_og_list'] != '':
						acl_source_destination_port_list = list(itertools.product(source_ips, destination_ips, destination_ports, acl_protocol_items))	
					else:
						acl_source_destination_port_list = list(itertools.product(source_ips, destination_ips, destination_ports))	
					
					print("")
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
						acl_protocol = ''
						acl_source_full = list_item[0].split()
						acl_source_host_id = acl_source_full[0]
						if len(acl_source_full) >1:
							acl_source_host_sn = acl_source_full[1]	
						acl_dst_full = list_item[1].split()
						acl_dst_host_id = acl_dst_full[0]
						if len(acl_dst_full) >1:
							acl_dst_host_sn = acl_dst_full[1]	
						acl_dst_port = list_item[2]
						if item[u'acl_source_og_list'] != '':
							acl_protocol_full = list_item[3].split()
							if len(acl_protocol_full) >1:
								acl_protocol = acl_protocol_full[0]
								acl_dst_port = acl_protocol_full[1]
							else:
								acl_protocol = ''
								acl_dst_port = list_item[2]
						else:
							acl_protocol = item[u'acl_protocol']

						new_csv_row = (int(item[u'acl_line_number']), acl_line_child, item[u'acl_interface'], item[u'acl_direction'], item[u'acl_name'], \
							item[u'inactive'], item[u'acl_type'], item[u'acl_action'], \
							item[u'acl_protocol_og'], item[u'acl_protocol_og_list'], \
							acl_source_host_id, acl_source_host_sn, acl_dst_host_id, acl_dst_host_sn, acl_dst_port, acl_protocol,\
							item[u'original_acl_line'])
						writer.writerow(new_csv_row)
					#print(new_csv_row)
					#writer.writerow(new_csv_row)
				else: # = remark
					new_csv_row = (int(item[u'acl_line_number']), acl_line_child, item[u'inactive'], item[u'acl_type'], '', '', \
							'' , '', '', '', '', '', '', item[u'original_acl_line'])
					writer.writerow(new_csv_row)

			
def get_og_content(parse, og_name, og_type):
	all_og_items_return = dict()
	og_rows_processed = 0
	# Get flattened list of items (nested groups splitted-out)
	og_items = list_all_object_group_items(parse, og_name, og_type)
	for og_item in og_items:
		og_rows_processed = og_rows_processed + 1
		if (debug):
			print("OG_ROW_PROCESSING : "), og_rows_processed
		og_item_words_total = len(og_item.split())
		og_item_words = og_item.split()
		og_dst_ports = ''	
		new_dict_line = ''

		if og_type == 'network':
			if og_item_words[0] != 'description' and og_item_words[0] != 'group-object' :
				# Check wether new object, group is used or valid IPv4 address
				if is_ipv4(og_item_words[1]):
					# 2nd and 3rd word are subnet and netmask
					new_dict_line = {'host_id': og_item_words[1], 'subnet': og_item_words[2]}
					all_og_items_return[og_rows_processed] = new_dict_line	
				elif og_item_words[1] == 'host':
					new_dict_line = {'host_id': og_item_words[2], 'subnet': '255.255.255.255'}
					all_og_items_return[og_rows_processed] = new_dict_line	
					#all_og_items.append(og_item_words[2] + " 255.255.255.255")
				elif og_item_words[1] == 'object':
					#if (debug):
					#print("SEARCHING FOR OBJECT")
					## get object items
					object_content = dict()
					object_content = get_object_content(parse, og_item_words[2], og_type)
					sub_key = 0
					for key, item in object_content.items():
						#print key, item
						new_dict_line = {'host_id': item[u'host_id'], 'subnet': item[u'subnet']}
						all_og_items_return[og_rows_processed, int(key)] = new_dict_line	
					#all_og_items.append(get_object_content(parse, og_item_words[2], og_type))
				elif og_item_words[1] == 'network':
					print("ERROR : TODO NETWORK TYPE" + og_item)
				else:
					raise ValidationError("ERROR: object-group type " + og_item_words[1] + " not found" + og_type, "get_og_content")
					print("ERROR: object-group type " + og_item_words[1] + " not found" + og_type)

			# Return Dict
			#new_dict_line = {'host_id': og_item_words[1], 'subnet': og_dst_ports}

				all_og_items_return[og_rows_processed] = new_dict_line	
		elif  og_type == 'service' or og_type == 'icmp':
			if og_item_words[1] == 'icmp':		# Service type icmp
				#Type ICMP possible
				if og_item_words_total > 2:
					og_dst_ports = og_item_words[2]
				#if no extra words in service-object than both directions are allowed
					new_dict_line = {'protocol': og_item_words[1], 'destination_port': og_dst_ports}
					all_og_items_return[og_rows_processed] = new_dict_line
			elif og_item_words[1] == 'tcp' or og_item_words[1] == 'udp' or og_item_words[1] == 'tcp-udp':		# Service type tcp/udp
				#check if one port or range
				if og_item_words_total > 2:
					if og_item_words[2] == 'destination' and  og_item_words[3] == 'eq': 
						og_dst_ports = og_item_words[4]
					elif og_item_words[2] == 'destination' and  og_item_words[3] == 'range': 
						# Range have two inputs, start and beginning
						og_dst_ports = og_item_words[4] + '-' + og_item_words[5]
					new_dict_line = {'protocol': og_item_words[1], 'destination_port': og_dst_ports}
					all_og_items_return[og_rows_processed] = new_dict_line									
				else:
					# Probably no extra words
					og_dst_ports = ''
					new_dict_line = {'protocol': og_item_words[1], 'destination_port': og_dst_ports}
					all_og_items_return[og_rows_processed] = new_dict_line

			elif og_item_words[0] == 'port-object' and og_item_words[0] != 'description' and og_item_words[0] != 'group-object':
				# we have icmp, tcp or udp service-objects
				if og_item_words[1] == 'eq':			# one port is
					og_dst_ports = og_item_words[2]
				elif og_item_words[1] == 'range':		# port-object range loop all items
					og_dst_ports = og_item_words[2] + '-' + og_item_words[3]
				else:
					raise ValidationError("ERROR: port-group type " + og_item_words[1] + " not found for type " + og_type, "get_og_content")
					print("ERROR: object-group type " + og_item_words[1] + " not found in " + og_type)							
				
				new_dict_line = {'protocol': og_item_words[1], 'destination_port': og_dst_ports}
				all_og_items_return[og_rows_processed] = new_dict_line



	#for key, item in all_og_items_return.items():
	#	print key, item


	return all_og_items_return

def get_object_content(parse, object_name, o_type):
	#Instead of object-group there are also objects 
	#og_types: protocol, network, service
	# network-object 
	indent_space = "     "
	# Create empyt list
	all_object_items = dict()
	dict_items = 0
	if o_type == 'network' or o_type == 'service':
		o_items = iter(parse.find_all_children('^object '+ o_type + ' ' + object_name + '', exactmatch=True))
		#skip first item
		try:
			next(o_items)
		except:
			print("ERROR! : get_og_content - first line not skipped")
		for o_item in o_items:
			dict_items = dict_items + 1
			o_item_words = o_item.split()
			#print(indent_space + o_item)
			if o_item_words[0] == 'subnet':
				#print(o_item_words[1])
				new_dict_line = {'host_id': o_item_words[1], 'subnet': o_item_words[2]}
				all_object_items[dict_items] = new_dict_line
			elif o_item_words[0] == 'host':
				new_dict_line = {'host_id': o_item_words[1], 'subnet': '255.255.255.255'}
				all_object_items[dict_items] = new_dict_line
			elif o_item_words[0] == 'description':
				o_item_desc = o_item[len("description "):]
			elif o_item_words[0] == 'range':
				# Returning IP addresses for the range
				range_start_ip = str(o_item_words[1])					# Changed 26-4 removed decode from str.decode possible Python3 not needed
				range_end_ip = str(o_item_words[2])						# Changed 26-4 removed decode from str.decode possible Python3 not needed
				IP_in_range = find_IP_in_range(range_start_ip, range_end_ip)
				for IP in IP_in_range:
					if (debug):
						print("In range IP :" + str(IP))
					new_dict_line = {'host_id': IP, 'subnet': '255.255.255.255'}
					#all_object_items.append(IP + " 255.255.255.255")
					all_object_items[dict_items] = new_dict_line

			else:
				print("ERROR OBJECT " + o_item_words[0] +  " TYPE NOT FOUND FOR " + object_name)
		return all_object_items
	else:
		print("ERROR OBJECT TYPE " + o_type + " NOT SUPPORTED")

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

def split_acl_lines(parse, acl_line, total_acl_lines, acl_line_number):
	
	acl_length = len(acl_line.split())
	indent_space = "     "
	acl_words = acl_line.split()
	# FILTER LINES, DONT PROCESS FURTHER
	skip_this_line = False
	acl_line_inactive = False


	if SKIP_INACTIVE == True and (get_acl_line_word(acl_line, acl_length) == 'inactive'):
		acl_line_inactive = True
		skip_this_line = True
		if PRINT_LINES == True:
			print(str(acl_line_number) + str(" : SKIPPED! Inactive !"))
	# Check if a time filter is used and is exceeded
	if SKIP_TIME_EXCEEDED == True and (get_acl_line_word(acl_line, acl_length-1) == 'time-range'):
		skip_this_line = True
		# RUN FUNCTION TO CHECK TIME AND RETURN SKIP TRUE OR FALSE
		if PRINT_LINES == True:
			print(str(acl_line_number) + str(" : SKIPPED! time-range exceeded !"))

	if (skip_this_line != True):
		if PRINT_LINES == True:
			if (python3):
				print(acl_line_number, end="", flush=True)
				print(" : ", end="", flush=True)
				print(acl_line, flush=True)
			else:
				print(acl_line_number),
				print(" : "), 
				print(acl_line)

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
	acl_protocol_og_items_list = ''
	acl_protocol_og = ''
	acl_protocol = ''
	acl_source_in_og = False
	acl_source_og_list = '' 			# Building list for output dict
	acl_source_sn = ''
	acl_source_nm = ''
	acl_source_og = ''
	acl_dst_in_og = False
	acl_dst_sn = ''
	acl_dst_nm = ''
	acl_dst_og = ''
	acl_dst_ports_in_og = False 
	acl_dst_ports_og_items_list = ''
	acl_dst_og_list = ''
	acl_dst_ports_og  = ''
	acl_dst_ports = ''
	acl_dst_ports_og_items = ''


	# define empty variables
	#print(acl_line)
	acl_type = get_acl_line_word(acl_line, acl_type_section)
	if acl_type != 'remark':
		

		acl_action = get_acl_line_word(acl_line, acl_action_section)
		acl_protocol = get_acl_line_word(acl_line, acl_protocol_section)
		#check if protocl is object-group
		if acl_protocol == 'object-group':
			acl_protocols_in_og = True
			acl_protocol_og = get_acl_line_word(acl_line, acl_protocol_section+1)
			acl_protocol_og_items = get_og_content(parse, acl_protocol_og, 'service') 	# section holds the object-group type. Can be 'service' or 'protocol
			# Create list for print and export
			acl_protocol_og_items_list = list()
			for key, item in acl_protocol_og_items.items():
				if item[u'destination_port'] != '':
					acl_protocol_og_items_list.append(item[u'protocol'] + " " + item[u'destination_port']) 
				else:
					acl_protocol_og_items_list.append(item[u'protocol'])

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
			acl_source_sn = ''
			acl_source_og = get_acl_line_word(acl_line, acl_src_ip_section+1)
			acl_source_og_items = get_og_content(parse, acl_source_og, 'network')
			# Create list for print and exrpot -> Must be optimized
			acl_source_og_list = list()

			for key, item in acl_source_og_items.items():
				if is_ipv4(item[u'host_id']) and is_ipv4(item[u'subnet']):
					acl_source_og_list.append(item[u'host_id'] + " " + item[u'subnet']) 
		elif acl_source_sn == 'object':    # Added object 19-4-18 
			acl_source_in_og = True
			acl_source_og = get_acl_line_word(acl_line, acl_src_ip_section+1)
			acl_source_og_items = get_object_content(parse, acl_source_og, 'network')		
			for key, item in acl_source_og_items.items():
				#print key, item
				acl_source_sn = item[u'host_id']
				acl_source_nm = item[u'subnet']
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
			acl_dst_sn = ''
			acl_dst_og = get_acl_line_word(acl_line, acl_dst_ip_section+1)
			acl_dst_og_items = get_og_content(parse, acl_dst_og, 'network')	
			# Create Destination list, needed by print and export (MUST BE IMPROVED)
			acl_dst_og_list = list()
			for key, item in acl_dst_og_items.items():
				if is_ipv4(item[u'host_id']) and is_ipv4(item[u'subnet']):
					acl_dst_og_list.append(item[u'host_id'] + " " + item[u'subnet']) 			
				else:
					print("ERROR! Destination OG host or subnet is not valid")
		elif acl_dst_sn == 'object':    # Added object 19-4-18 
			acl_dst_in_og = True
			acl_dst_og = get_acl_line_word(acl_line, acl_dst_ip_section+1)	
			acl_dst_og_items = get_object_content(parse, acl_dst_og, 'network')
			for key, item in acl_dst_og_items.items():
				#print key, item
				acl_dst_sn = item[u'host_id']
				acl_dst_nm = item[u'subnet']
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

				# we need to extend the port object-name with the protocol by acl destination port groups
				if acl_protocol == 'udp' or acl_protocol == 'tcp':
					acl_dst_ports_og = acl_dst_ports_og + ' ' + acl_protocol  		# 23-04 changed to next line because protocol can be tcp, udp OR both
					#acl_dst_ports_og = acl_dst_ports_og + ' ' + get_acl_line_word(acl_line, acl_port_section+2)
					acl_dst_ports_og_items = get_og_content(parse, acl_dst_ports_og, 'service')
					# Create list for export
					acl_dst_ports_og_items_list = list()

					for key, item in acl_dst_ports_og_items.items():
						#acl_dst_ports_og_items_list.append(acl_protocol + " " + item[u'destination_port']) 
						#Check if item is string (named port) or number
						#acl_dst_port_item = replace_port_name_to_number(item[u'destination_port'])
						acl_dst_port_item = item[u'destination_port']
						acl_dst_ports_og_items_list.append(acl_dst_port_item) 

				if acl_protocol == 'icmp':
					acl_dst_ports_og_items = get_og_content(parse, acl_dst_ports_og, 'icmp')
				if (debug):
					print("ACL DST PORTS ITEMS"), acl_dst_ports_og_items
				# CREATE EXTRA CHECK THAT THE OG HAVE SAME PROTOCOL MATCHING? NEED TO CHANGE function
				

			# if word is time-range followed by time setting. This is a temporary rule




	# PRINT 
	if acl_type != 'remark' and not skip_this_line and (PRINT_FULL_OUTPUT):
		print("acl_type : " + acl_type)
		print("acl_action : " + acl_action)

		
		print("******* SOURCE: *******")
		if acl_source_og != '':
			print("acl_source_og : " + acl_source_og)
			for item in acl_source_og_list:
				acl_source_word = item.split()
				print(indent_space + indent_space + "host_id : " + acl_source_word[0]),
				print(" subnet : " + acl_source_word[1])
		else:
			print("acl_source_sn : " + acl_source_sn)
			print("acl_source_nm : " + acl_source_nm) 
		print("****** DESTINATION: ******")
		if acl_dst_og != '':
			print("acl_dst_og : " + acl_dst_og)
			for item in acl_dst_og_list:
				acl_dst_word = item.split()
				print(indent_space + indent_space + "host_id : " + acl_dst_word[0]),
				print(" subnet : " + acl_dst_word[1])

		

		else:
			print("acl_dst_sn : " + acl_dst_sn)
			print("acl_dst_nm : " + acl_dst_nm) 
		
		# DESTINATION PORTS
		if (acl_protocols_in_og):
			print("******** PORTS: ********")
			print("acl_protocol_og: " + acl_protocol_og)
			print(indent_space + "og_objects: ")
			#RETURN IS DICTIONARY, CREATE LOOP
			for item in acl_protocol_og_items_list:
				acl_dst_ports_words = item.split()
				print(indent_space + indent_space + "protocol " + acl_dst_ports_words[0]),
				if len(acl_dst_ports_words) > 1 :
					print("destination port " + acl_dst_ports_words[1])
				else:
					print("")
			 	

		else:


			if acl_dst_ports_og != '':
				print("******** PORTS: ********")
				print("acl_dst_ports_og : " + acl_dst_ports_og) 
				for item in acl_dst_ports_og_items_list:
					acl_dst_ports_words = item.split()
					print(indent_space + indent_space + "protocol " + acl_dst_ports_words[0]),
					if len(acl_dst_ports_words) > 1:
						print("destination port " + acl_dst_ports_words[1])
					else:
						print("")

			elif acl_port_words > 0:
				print("******** PORTS: ********")
				
				# Check if we have a string or list
				if is_obj_string(acl_dst_ports) == True:
					print(indent_space + "protocol " + acl_protocol), 
					print("destination port : "),
					print(acl_dst_ports)
				else:
					print(indent_space + "protocol " + acl_protocol), 
					print("destination port : "),
					for i in acl_dst_ports:
						print(i),
					print("")
			elif acl_protocol == 'ip' or acl_protocol == 'icmp':
				print("******** PORTS: ********")
				print(indent_space + "protocol " + acl_protocol)
			else:
				print("ERROR!! NO destination ports extracted!!")
			
	
	if (CREATE_DICT):
		
		new_dict_line = {'acl_line_number': acl_line_number,
			'acl_interface': '',
			'acl_direction': '',
			'acl_name': '',
			'inactive': acl_line_inactive,
			'acl_type': acl_type,
			'acl_action': acl_action,
			'acl_protocol': acl_protocol,
			'acl_protocol_og': acl_protocol_og,
			'acl_protocol_og_list': acl_protocol_og_items_list,
			'acl_source_og': acl_source_og,
			'acl_source_og_list': acl_source_og_list,
			'acl_source_sn': acl_source_sn,
			'acl_source_nm': acl_source_nm,
			'acl_dst_og': acl_dst_og,
			'acl_dst_og_list': acl_dst_og_list,
			'acl_dst_sn': acl_dst_sn,
			'acl_dst_nm': acl_dst_nm,
			'acl_dst_ports_og': acl_dst_ports_og,
			'acl_dst_ports_og_items_list': acl_dst_ports_og_items_list,
			'acl_dst_ports': acl_dst_ports,
			'original_acl_line': ''
			}
		

	return new_dict_line

def replace_port_name_to_number(name):
	# Dict needs to be replaced by CSV import!
	if is_obj_string(name):
		#print("DESTINATION PORT OG IS WORD!!!!!")
		name = 'http'
		d = {
			'http': '80',
			'https': '443',
			'ldap': '389',
			'ldaps': '636',
		}
		pattern = re.compile(r'\b(' + '|'.join(d.keys()) + r')\b')
		result = pattern.sub(lambda x: d[x.group()], name)
		return result
	else:
		return name

def find_IP_in_range(start, end):
	# Need ipaddress or ipaddr library
	start = ip_address(start)
	end = ip_address(end)
	result = []
	while start <= end:
		result.append(str(start))
		start += 1
	return result

def list_all_object_group_items(parse, main_group, og_type):
	all_object_groups_items = list()

	if og_type == 'network' or og_type == 'service' or og_type == 'icmp':
		if (debug):
			print("OBJECT-GROUP CONTENT : object-group " + og_type.strip() +" " + main_group.strip())
		try:
			og_items = iter(parse.find_all_children('object-group '+ og_type.strip() +' '+ main_group.strip(), exactmatch=True))
			#itercars = iter(cars)
			next(og_items)
		except:
			#Try an protocol object group with same name, some service- OG (beginning ACL) have reference to protocol only
			try:
				og_items = iter(parse.find_all_children('object-group protocol '+ main_group.strip(), exactmatch=True))
				#itercars = iter(cars)
				next(og_items)
			except:
				#Try to use an tcp-udp object-group - this van be linked as port OG when there is an source OG where protocols are used (see above exept)
				try:
					og_items = iter(parse.find_all_children('object-group '+ og_type.strip() +' '+ main_group.strip() +' tcp-udp', exactmatch=True))
					#itercars = iter(cars)
					next(og_items)
				except:				
					print("ERROR: Object-group " + main_group.strip() + " not found for type " + og_type)

		for og_item in og_items:
			#print(og_item)		
			og_item_words = og_item.split()
			if og_item_words[0] != 'group-object' and og_item_words[0] != 'description':
				#print("   NESTED GROUP : " + og_item_words[1])
				all_object_groups_items.append(og_item)
			elif og_item_words[0] == 'group-object':
				#next_group = extract_nested_object_groups(parse, og_type, og_item_words[1])
				all_object_groups_items.append(list_all_object_group_items(parse, og_item_words[1], og_type))

	#Flatten the list
	all_object_groups_items = flatten(all_object_groups_items)
	return all_object_groups_items

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

def get_nameif_interfaces(parse):
	interfaces = []
	interfaces = [obj for obj in parse.find_objects(r"^interface Ethernet1/3.4") \
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

def main():
	print("Read config file")

	parse = parseconfig(input_config_file)
	pprint(parse)

	# Only READ IN ONCE! = Global
	global network_routes	
	network_routes = dict()
	network_routes = get_network_routes(parse, True)

	global extracted_acl_lines
	extracted_acl_lines = dict()

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

	#print("ALL ACL LINE DICT!!:")
	#pprint(extracted_acl_lines)


if __name__ == "__main__":
	main()