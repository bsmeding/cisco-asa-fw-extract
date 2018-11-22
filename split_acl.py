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
import logging
import datetime

# Import ipaddress library based on Python version (2.x of 3.2 = ipaddr >3.2 ipaddres) used to calculate ip addresses in range
try:
    from ipaddress import ip_address
except ImportError:
    from ipaddr import IPAddress as ip_address

#Check Python version
if sys.version_info[0] >= 3:
	python3 = True
	open_csv_writemode = 'w'
else:
	python3 = False
	open_csv_writemode = 'wb'

import pandas as pd


PRINT_REMARKS = False			# True for print to screen, False no print to screen. Default: False
PRINT_LINES = False 			# Print line info. Default: False
EXPORT_TYPE = 'csv' 			# Export ACL Lines to 'excel' or to 'csv'. Default: csv
EXPORT_TO_TABS = True 			# In case of excel, export each ACL to new TAB 
EXPORT_REMARKS = False 			# Skip the remark lines in export output. Default: False
EXPORT_ORIGINAL_LINE = True 	# Export the original ACL line (takes longer, and more export data). Default: True
debug = False 					# Debug mode - high print output! Default: False
debug_export = False
SHOW_ACL_EXTRACTION = False 	# Show the extraction of each ACL line,(also shown when debug enabled)
CREATE_DICT = True 				# Maybe remove! Default: True
EXTRACT_PORT_RANGES = False
#EXPORT_ACL_SEPERATE_FILES = False 	# Export each ACL to separate file

#input_config_file = "confsmall.conf" 
input_config_file = "ciscoconfig.conf" 

input_dir = 'conf_input'

#output_csv_file = "acl_seperated.csv"
output_dir = 'acl_output/'
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


"""


now = datetime.datetime.now()
filename_log = './log/logging_' + str(now.year) + '_'+ str(now.month) + '_'+ str(now.day) + '-'+ str(now.hour) + '_'+ str(now.minute) + '.log'
logging.basicConfig(filename=filename_log,level=logging.INFO)



def parseconfig(filename):
	return CiscoConfParse(filename, ignore_blank_lines=True,  syntax='asa')


def status_update(status , print_marks, severity, debug):
	mark_indent = 10
	log_level = severity.lower()

	if log_level == 'info' :
		# INFO ONLY TO LOG FILE
		logging.info(status)
		#EXCEPT IN DEBUG MODE
		if (debug==True):
			print("INFO: " + str(status))	
	elif log_level == 'warning':
		logging.warning("*" * 40)
		logging.warning(status)
		logging.warning("*" * 40)
		print("WARNING: " + str(status))
	elif log_level == 'critical':
		logging.critical("*" * 40)
		logging.critical(status)
		logging.critical("*" * 40)
		print("CRITICAL: " + str(status))
	else:
		print(str(log_level) + " - " + status)	


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

def replace_port_name_to_number(name):
	# Note portDict is read in Globally from CSV file!
	# This returns input back if no match found
	portNumber = re.sub(r'\b'+name+r'\b', lambda m: portDict.get(m.group(), m.group()), name)    	
	#portNumber = re.sub(r'\b'+name+r'\b', lambda m: portDict.get(m.group()), name)					# This returns nothing when not found in dict
	return portNumber


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
				#print(file_name)
				#print(file_name_path)   # This is the full path of the filter file
				new_dict_line = {'file_name': file_name, 'file_path': file_name_path}
				config_files[file_counter] = new_dict_line
	return config_files

def create_og_dict(parse):
	#print(">>>>>>>>>>>>>>>>>> OPMAKEN OG_DICT")
	#Opmaken object dictionary alleen met objects (objet-group is apart) dit gaat PER config en wordt dus alleen met analyze geladen.
	og_dict = dict()			# Dict met alle object-groups
	og_network_dict = dict()	# Dict met alleen netweork object-groups
	og_service_dict = dict()	# Dict met alleen services object-groups



	og_items = parse.find_objects("^object-group ")
	og_network_items = parse.find_objects('^object-group network\s')
	og_service_items = parse.find_objects('^object-group service\s')
	og_protocol_items = parse.find_objects('^object-group protocol\s')
	#pprint(og_service_items)
	#print(len(og_network_items))
	#print(len(og_service_items))
	#print("totaal : " + str((len(og_network_items) + len(og_service_items) ))) 
	#print(len(og_items))
	og_rows_processed = 0
	for og_netw_item in og_network_items:
		tcp_ports_list = list()
		udp_ports_list = list()
		protocol_only_list = list()
		icmp_ports_list = list()		
		#print(og_netw_item.text)
		og_rows_processed += 1
		#leeg maken lijsten voor export
		network_objects = list()								# Alle netwerk objecten (host en subnets)
		sub_og_list = list()									# Nested object-groups in list form
		if (debug):
			print("OG_ROW_PROCESSING : ", og_rows_processed)
		og_children = parse.find_all_children(og_netw_item.text, exactmatch=True)
		og_items_to_process = len(og_children)					# Voor validatie dat we alle regels processen
		og_items_processed = 0									# Nu op 0 zetten, per regel ophoven en aan einde van de loop controleren of even veel is
		# In OG_children zit ook de OG naam
		og_name = og_children[0]

		o_item_desc = ''
		for og_item in og_children:
			subnet_cidr = ''
			host_cidr = ''
			if (debug):
				print(og_item)
			og_item_words = og_item.split()
			if og_item_words[0] == 'description':
				og_items_processed += 1
				o_item_desc = og_item[len("description  "):]
			elif og_item_words[0] == 'network-object' and og_item_words[1] != 'host':
				og_items_processed += 1
				
				if og_item_words[1] != 'object':
					subnet_cidr = og_item_words[1] + "/" + str(netmask_to_cidr(og_item_words[2]))
					network_objects.append(subnet_cidr)
				else:
					subnet_cidr = get_object_item(parse, 'network', str(og_item_words[2]))
					network_objects.append(subnet_cidr)
				if (debug):
					print("Subnet IP " + str(og_item_words[1]) + " / " + str(og_item_words[2]))
			elif og_item_words[0] == 'network-object' and og_item_words[1] == 'host':
				og_items_processed += 1
				host_cidr = og_item_words[2] + "/32"
				network_objects.append(host_cidr)
				if (debug):
					print("HOST IP " + str(host_cidr))
			elif og_item_words[0] == 'group-object':
				# Dit is de regel zelf, die wordt met Children nog een keer weergegeven. Deze wel tellen, maar niets mee doen
				og_items_processed += 1
				nested_og_type = og_item_words[1]
				if (debug):
					print("Nested Group-Object group:" + str(og_netw_item.text) + "  " + str(og_item_words[1]))
					print(len(og_item_words))
				sub_og_list.append(og_item_words[1])
			elif og_item_words[0] == 'object-group':
				# Dit is de regel zelf, die wordt met Children nog een keer weergegeven. Deze wel tellen, maar niets mee doen
				og_items_processed += 1
			else:
				print("ERROR! Geen OG process voor " + str(og_netw_item.text) + " CHILD: " + str(og_item))

		if og_items_to_process != og_items_processed:
			print("ERROR! Niet alle regels kunnen processen voor OG " + str(og_netw_item.text))

		
		og_name = og_name[len("object-group network "):]
		#print(og_name)
		#og_network_dict[og_name]={'desciption': o_item_desc, 'network_objects_list': network_objects, 'sub_og_list': sub_og_list}
		og_dict[og_name]={'og_type': 'network', 'desciption': o_item_desc, 'network_objects_list': network_objects, 'service_tcp_ports_list': tcp_ports_list,  'service_udp_ports_list': udp_ports_list, 'service_protocol_only_list': protocol_only_list, 'service_icmp_ports_list': icmp_ports_list,'sub_og_list': sub_og_list}


	# Nu services object-groups
	for og_service_item in og_service_items:
		#print(og_service_item.text)
		og_rows_processed += 1
		#leeg maken lijsten voor export
		o_item_desc = ''
		tcp_ports_list = list()
		udp_ports_list = list()
		protocol_only_list = list()
		icmp_ports_list = list()
		sub_og_list = list()									# Nested object-groups in list form
		
		og_children = parse.find_all_children(og_service_item.text, exactmatch=True)
		og_items_to_process = len(og_children)					# Voor validatie dat we alle regels processen
		og_items_processed = 0									# Nu op 0 zetten, per regel ophoven en aan einde van de loop controleren of even veel is
		# In OG_children zit ook de OG naam
		og_name = og_children[0]
		if (debug):
			print("OG_ROW_PROCESSING : " +  str(og_rows_processed) + " Name " + str(og_name) )
		og_name_items = og_name.split()
		port_og = False
		if len(og_name_items) >3:
			port_og = True
			port_og_protocol = og_name_items[3]
		if (debug):
			print("OG NAAM: " + str(og_children[0]))
		for og_item in og_children:
			subnet_cidr = ''
			host_cidr = ''
			
			#print(og_item)
			#if (debug):
			#print(og_item)
			og_item_words = og_item.split()		
			#Controleren of het een service groep of port-object groep is. Oftewel kunnen er meerdere protocollen zijn, of maar 1. Dit aan de hand van de aantallen worden
			if og_item_words[0] == 'description':
				og_items_processed += 1
				o_item_desc = og_item[len("description  "):]
			elif og_item_words[0] == 'port-object':
				
				#dan moet ook port_og_protocol bekend zijn, dit kunnen alleen items van hetzelfde protocol zijn
				#if (port_og):
				#	#Nu achterhalen of het een enkele poort of een range is
				if og_item_words[1] == 'eq':
					#Enkele poort
					og_port = og_item_words[2]
					
					if is_obj_string(og_port) == True:
						og_port_number = replace_port_name_to_number(og_port)
					else:
						og_port_number = og_port_number
					if port_og_protocol == 'tcp':
						tcp_ports_list.append(og_port_number)
						og_items_processed += 1
					elif port_og_protocol == 'udp':
						udp_ports_list.append(og_port_number)
						og_items_processed += 1
					elif port_og_protocol == 'icmp':
						icmp_ports_list.append(og_port_number)
						og_items_processed += 1
					elif port_og_protocol == 'ip' or port_og_protocol == 'esp':
						protocol_only_list.append(port_og_protocol)
						og_items_processed += 1
					elif port_og_protocol == 'tcp-udp':
						tcp_ports_list.append(og_port_number)
						udp_ports_list.append(og_port_number)
						og_items_processed += 1							
					else:
						status_update("ERROR! port-object groep gevonden maar geen items! " + str(port_og_protocol) + " port " + str(og_port_number) , False, 'critical', debug)
						
					#print("port: " + str(og_port) + "( " + acl_dst_port_number + " )")
				elif og_item_words[1] == 'range':
					range_start = int(replace_port_name_to_number(og_item_words[2]))
					range_end = int(replace_port_name_to_number(og_item_words[3]))
					if EXTRACT_PORT_RANGES:
						try:

							for i in range(range_start, range_end+1):
								if port_og_protocol == 'tcp':
									tcp_ports_list.append(i)
								elif port_og_protocol == 'udp':
									udp_ports_list.append(i)
								elif port_og_protocol == 'icmp':
									icmp_ports_list.append(i)
								else:
									protocol_only_list.append(port_og_protocol)
								og_items_processed += 1
						except:
							#Fallback if protocol name not resolvable is to a number
							if port_og_protocol == 'tcp':
								tcp_ports_list.append(str(range_start) + "-" + str(range_end))
							elif port_og_protocol == 'udp':
								udp_ports_list.append(str(range_start) + "-" + str(range_end))
							elif port_og_protocol == 'icmp':
								icmp_ports_list.append(str(range_start) + "-" + str(range_end))							
						status_update("Range in " + str(og_name) + " deze uit elkaar halen :" + str(og_item_words[2]) + "-"+ str(og_item_words[3]) , False, 'info', debug)	
					else:
						if port_og_protocol == 'tcp':
							tcp_ports_list.append(str(range_start) + "-" + str(range_end))
						elif port_og_protocol == 'udp':
							udp_ports_list.append(str(range_start) + "-" + str(range_end))
						elif port_og_protocol == 'icmp':
							icmp_ports_list.append(str(range_start) + "-" + str(range_end))											
					
						
				else:
					status_update("Geen port-objects gevonden voor " +str(og_item_words[1]) , False, 'warning', debug)

				#else:
				#	status_update("ERROR! Wel port-object maar geen og_protocol gevonden" , False, 'critical', debug)
			elif og_item_words[0] == 'service-object':
				#print(og_item)

				#Service object, deze bevatten zowel protocol als port en evt een range
				port_og_protocol = og_item_words[1]
				if len(og_item_words) <3:
					#alleen een protocol
					protocol_only_list.append(port_og_protocol)
					og_items_processed += 1
					if (debug):
						print("service group protocol only : " + str(port_og_protocol))
				else:
					#print(og_port)
					if og_item_words[2] == 'eq':
						og_port = og_item_words[3]
						if is_obj_string(og_port) == True:
							og_port_number = replace_port_name_to_number(og_port)
						else:
							og_port_number = og_port_number
						if port_og_protocol == 'tcp':
							tcp_ports_list.append(og_port_number)
							og_items_processed += 1
						elif port_og_protocol == 'udp':
							udp_ports_list.append(og_port_number)
							og_items_processed += 1
						elif port_og_protocol == 'tcp-udp':
							tcp_ports_list.append(og_port_number)
							udp_ports_list.append(og_port_number)
							og_items_processed += 1	
						elif port_og_protocol == 'ip' or port_og_protocol == 'esp':
							protocol_only_list.append(port_og_protocol)
							og_items_processed += 1
					elif og_item_words[1] == 'icmp':
						icmp_type = og_item_words[2]
						if is_obj_string(icmp_type) == True:
							icmp_type = replace_port_name_to_number(icmp_type)
						icmp_ports_list.append(icmp_type)
						og_items_processed += 1

					elif og_item_words[2] == 'range':
						range_start = int(replace_port_name_to_number(og_item_words[3]))
						range_end = int(replace_port_name_to_number(og_item_words[4]))
						if (EXTRACT_PORT_RANGES):

							for i in range(range_start, range_end+1):
								if port_og_protocol == 'tcp':
									tcp_ports_list.append(i)
								elif port_og_protocol == 'udp':
									udp_ports_list.append(i)
								elif port_og_protocol == 'tcp-udp':
									tcp_ports_list.append(i)
									udp_ports_list.append(i)
								elif port_og_protocol == 'icmp':
									icmp_ports_list.append(i)
								else:
									protocol_only_list.append(port_og_protocol)
								og_items_processed += 1
						else:
							if port_og_protocol == 'tcp':
								tcp_ports_list.append(str(range_start) + "-" + str(range_end))
							elif port_og_protocol == 'udp':
								udp_ports_list.append(str(range_start) + "-" + str(range_end))
							elif port_og_protocol == 'icmp':
								icmp_ports_list.append(str(range_start) + "-" + str(range_end))									

					else:
						print("No service-objects found for " + str(port_og_protocol) + "  in " + str(og_item))



			elif og_item_words[0] == 'group-object':
				# Dit is de regel zelf, die wordt met Children nog een keer weergegeven. Deze wel tellen, maar niets mee doen
				og_items_processed += 1
				nested_og_type = og_item_words[1]
				if (debug):
					print("Nested GROUP-OBJECT " + str(og_item_words[1]) + "  in " + str(og_service_item.text))
				#print(len(og_item_words))
				sub_og_list.append(og_item_words[1])

			elif og_item_words[0] == 'object-group':

				# Dit is de regel zelf, die wordt met Children nog een keer weergegeven. Deze wel tellen, maar niets mee doen
				og_items_processed += 1
				if og_item != og_service_item.text:
					print("other OG nested: " + str(og_item) + "  in " + str(og_service_item.text) + " og_name: " + str(og_name))

			else:
				print("ERROR! NO og_functie for child: " + str(og_item_words[0]))
				print(og_children)


		og_name = og_name[len("object-group service "):]
		og_name = og_name.split(' ',1)[0]
		#og_service_dict[og_name]={'desciption': o_item_desc, 'network_objects_list': network_objects, 'sub_og_list': sub_og_list}
		#print(og_name)
		og_dict[og_name]={'og_type': 'service', 'desciption': o_item_desc, 'network_objects_list': [], 'service_tcp_ports_list': tcp_ports_list,  'service_udp_ports_list': udp_ports_list, 'service_protocol_only_list': protocol_only_list, 'service_icmp_ports_list': icmp_ports_list,'sub_og_list': sub_og_list}


	#print("PROTOCOL OGs " + str(og_protocol_items))
	for og_protocol_item in og_protocol_items:
		protocol_only_list = list()
		og_rows_processed += 1
		#leeg maken lijsten voor export
		sub_og_list = list()									# Nested object-groups in list form
		if (debug):
			print("OG_ROW_PROCESSING : ", og_rows_processed)
		
		og_children = parse.find_all_children(og_protocol_item.text, exactmatch=True)
		og_items_to_process = len(og_children)					# Voor validatie dat we alle regels processen
		og_items_processed = 0									# Nu op 0 zetten, per regel ophoven en aan einde van de loop controleren of even veel is
		# Get OG_NAME
		og_name = og_children[0]
		og_name = og_name[len("object-group protocol "):]
		og_name = og_name.split(" ", 1)[0]
		for og_item in og_children:
			og_item_words = og_item.split()	
			if og_item_words[0] == 'protocol-object':
				og_items_processed += 1
				#print("Protocol object! : " + str(og_item_words[1]))
				protocol_only_list.append(og_item_words[1]) 
			elif  og_item_words[0] == 'object-group':
				# This is parent row
				og_items_processed += 1
			else:
				print("NO Protocol object found!")

		og_dict[og_name]={'og_type': 'protocol', 'desciption': o_item_desc, 'network_objects_list': [], 'service_tcp_ports_list': [],  'service_udp_ports_list': [], 'service_protocol_only_list': protocol_only_list, 'service_icmp_ports_list': icmp_ports_list,'sub_og_list': sub_og_list}


	#pprint(og_dict)
	return og_dict

def get_hostname(parse):
	hostname_row = parse.find_lines(r'^hostname ')
	hostname_row = hostname_row[0]
	hostname = hostname_row.strip()[len("hostname "):] 
	return hostname

def get_object_item(parse, object_type, object_name):
	object_item = "+ object " + object_type + " " + object_name
	#print("zoeken naar " + str(object_item))
	og_items_processed = 0
	object_cidr = ''
	og_children = parse.find_all_children(r'^object ' + object_type + ' ' + object_name, exactmatch=True)
	#print(og_children)
	for og_item in og_children:
		
			
		og_item_words = og_item.split()		
		#Controleren of het een service groep of port-object groep is. Oftewel kunnen er meerdere protocollen zijn, of maar 1. Dit aan de hand van de aantallen worden
		if og_item_words[0] == 'description':
			og_items_processed += 1
		elif og_item_words[0] == 'object':
			og_items_processed += 1	
			#eigen regel 	
		elif og_item_words[0] == 'host':
			og_items_processed += 1	
			object_cidr =  og_item_words[1] + '/32'
		elif og_item_words[0] == 'subnet':
			og_items_processed += 1	
			object_cidr =  og_item_words[1] + '/' + str(netmask_to_cidr(og_item_words[2]))
		else:
			print(og_item_words[0])

	return object_cidr
			

def get_nameif_interfaces(parse):
	interfaces = []
	interfaces = [obj for obj in parse.find_objects(r"^interf") \
    	if obj.re_search_children(r"nameif")]
	return interfaces

def get_acl_in(parse, nameif):
	#active_acls = parse.find_objects(r'accesss-group\s+(.*)\s+in\s+interface')
	for acl in parse.find_objects(r'access-group\s'):
		if nameif in acl.text and 'in interface' in acl.text:
			acl_name = acl.text
			acl_name = acl_name.split(' ', 2)[1]
			return(acl_name)

def get_acl_out(parse, nameif):
	#active_acls = parse.find_objects(r'accesss-group\s+(.*)\s+in\s+interface')
	for acl in parse.find_objects(r'access-group\s'):
		if nameif in acl.text and 'out interface' in acl.text:
			acl_name = acl.text
			acl_name = acl_name.split(' ', 2)[1]
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

def get_network_og_items(og_name, acl_og_items):
	og_network_source_items = og_dict.get(og_name)
	#print(og_network_source_items)
	acl_og_items = (og_network_source_items['network_objects_list'])
	if og_network_source_items['sub_og_list'] != '':
		for og_sub_item in og_network_source_items['sub_og_list']:
			acl_og_items.append(get_network_og_items(og_sub_item, acl_og_items))
	return flatten( acl_og_items )

def get_service_og_items(og_name):
	global og_dict
	global acl_dst_port_tcp
	global acl_dst_port_udp
	global acl_dst_port_protocol
	global acl_dst_port_icmp
	acl_dst_port_tcp = list()
	acl_dst_port_udp = list()
	acl_dst_port_protocol = list()
	acl_dst_port_icmp = list()
	sub_og_list = list()
	#print(og_dict.get(og_name))
	try:
		og_source_items = og_dict.get(og_name)
		acl_dst_port_tcp.extend(og_source_items['service_tcp_ports_list'])
		acl_dst_port_udp.extend(og_source_items['service_udp_ports_list'])
		acl_dst_port_protocol.extend(og_source_items['service_protocol_only_list'])
		acl_dst_port_icmp.extend(og_source_items['service_icmp_ports_list'])
		sub_og_list = og_source_items['sub_og_list'] 
		
		
	except:
		pass 
		#print(og_dict.get(og_name))
		print("ERROR! NO service group objects extract from " + str(og_name))

	return acl_dst_port_tcp, acl_dst_port_udp, acl_dst_port_protocol, acl_dst_port_icmp, sub_og_list

def get_acl_lines(parse, total_acl_lines, acl_name, acl_interface, acl_direction):
	"""
	Get ACL line by line and parse to split_acl_lines to analyse per word

	"""

	parsed_remark_lines = 0
	parsed_acl_lines = 0
	parsed_unknown_lines = 0
	# Create empty dictionary for object-groups - global so every module can use the items. And in de get_acl_lines so every new config will recreate the dict
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
			original_acl_line = acl_line
			#Start processed item logbook
			processed_acl_id += 1
			processed_acl_lines[processed_acl_id] = ({'acl_name': acl_name, 'acl_interface': acl_interface, 'acl_line_number': acl_line_number,'acl_line_child': '', 'acl_type': acl_line.partition(' ')[0], 'original_acl_line': acl_line,'acl_processed': False, 'reason':''})

			# First check if remark or ACL type
			if acl_line.partition(' ')[0] == 'remark':
				parsed_remark_lines = parsed_remark_lines + 1
				
				status_update("REMARK - " + str(acl_line_number) + " : " + str(acl_line) , False, 'info', debug)
				if (PRINT_REMARKS == True and PRINT_LINES == True):
					
					print(acl_line_number), ":",
					print(acl_line)
				if EXPORT_REMARKS == True:
					total_acl_lines += 1	
					# Go further and split ACL
					new_dict_line = {'acl_line_number': acl_line_number, \
						'acl_line_child': '', \
						'acl_type': '', \
						'acl_interface': acl_interface, \
						'acl_direction': acl_direction, \
						'acl_name': acl_name, \
						'inactive': '', \
						'acl_source_cidr': '', \
						'acl_source_protocol': '', \
						'acl_source_port': '', \
						'acl_dst_cidr': '', \
						'acl_dst_protocol': '', \
						'acl_dst_port': '', \
						'acl_logging': '', \
						'acl_interface': acl_interface, \
						'acl_logging_severity': '', \
						'original_acl_line': original_acl_line \
						}
					acl_line_dict[total_acl_lines] = new_dict_line

					#Update processed item logbook, item processed now
					processed_acl_lines[processed_acl_id].update({'acl_processed': True})


				else:
					processed_acl_lines[processed_acl_id].update({'reason': 'export_remark is False'})

					
			elif acl_line.partition(' ')[0] == 'extended':
				parsed_acl_lines += 1

				#if (PRINT_LINES) or (debug):
				status_update("ACL    - " + str(acl_line_number) + " : " + str(acl_line) , False, 'info', debug)

				acl_line_child = 0
				acl_inactive = False
				acl_logging = False
				parsed_acl_lines = parsed_acl_lines + 1	
				

				# First set response processed line to false, maybe overwrite when there is information back from this lines
				processed_acl_lines[processed_acl_id].update({'acl_processed': False})
				processed_acl_lines[processed_acl_id].update({'reason': 'No input back from split_acl_lines'})

				#Split ACL Lines, word by word
				#remove log, debugging and inactive, so al the rest of the line will be the same type of items

				#remove extended
				acl_line = acl_line.partition(' ')[2]
			

				acl_protocol = ''
				og_service_name = ''
				og_network_source = ''
				acl_inactive = False
				acl_logging = False
				acl_logging_severity = ''
				acl_source_cidr = list()
				acl_dst_cidr = list()
				acl_dst_port_tcp = list()
				acl_dst_port_protocol = list()
				acl_dst_port_udp = list()
				acl_dst_port_icmp = list()

				if 'inactive' in acl_line:
					acl_inactive = True
					#strip inactive from line
					acl_line = acl_line.replace(' inactive', '')
				#logging line				
				if 'log' in acl_line:
					#print(acl_line)
					acl_logging = True
					#Check severity, remove rest of line
					try:
						acl_line, acl_logging_severity = acl_line.split(' log ',1)
					except:
						pass
						print(acl_logging_severity)
						print(acl_line)
				
				#number of object-groups
				acl_line_words = acl_line.split()
				#Permit or deny
				acl_type = acl_line_words[0]

				#print("ACL TYPE: " + str(acl_type))
				og_in_acl_line = 0
				og_service = 0						# A object-group for service is used, first te to 0
				og_network = 0
				og_port = 0
				

				og_in_acl_line = acl_line.count("object-group")
				acl_type = acl_line_words[0]
				#Remove 
				acl_line = acl_line.split(acl_type + ' ',1)[1]
				#print(acl_line)
				if acl_line_words[1] == "object-group":
					og_service = 1
					og_service_name = acl_line_words[2] 
					og_network = og_in_acl_line - 1
					
					acl_dst_port_tcp, acl_dst_port_udp, acl_dst_port_protocol, acl_dst_port_icmp, sub_og_list = get_service_og_items(og_service_name)
					acl_line = acl_line.split(acl_line_words[2] + ' ',1)[1]


				else:
					acl_protocol = acl_line_words[1]
					#print("PROTOCOL: " + str(acl_line_words[1]))
					acl_line = acl_line.split(acl_protocol + ' ',1)[1]

			
				#print(acl_line)
				acl_line_words = acl_line.split()
				if acl_line_words[0] == "any" or acl_line_words[0] == "any4":
					acl_source_cidr.append('0.0.0.0/0')
					#print(acl_source_cidr)
					acl_line = acl_line.split(acl_line_words[0] + ' ',1)[1]
				elif acl_line_words[0] == "object-group":
					acl_og_items = list()
					acl_source_cidr = get_network_og_items(acl_line_words[1], acl_og_items)
					#print(acl_source_cidr)
					acl_line = acl_line.split(acl_line_words[1] + ' ',1)[1]
				elif acl_line_words[0] == "host":
					acl_source_cidr.append(str(acl_line_words[1] + '/32'))
					#print("source host(s) ", acl_source_cidr)
					acl_line = acl_line.split(acl_line_words[1] + ' ',1)[1]
				elif is_ipv4(acl_line_words[0]):
					#ACL source is a subnet
					acl_source_cidr.append(str(acl_line_words[0]) + '/' + str(netmask_to_cidr(acl_line_words[1])))
					#print("source host(s) ", acl_source_cidr)
					acl_line = acl_line.split(acl_line_words[1] + ' ',1)[1]
				else:
					status_update(" NOT FOUND SOURCE ADDRESS OR SERVICE OG : " + str(acl_line_words[0]) , True, 'warning', debug)
					parsed_acl_lines -= 1
					parsed_unknown_lines += 1
				#print("restant na source split: " + str(acl_line))

				#Destination adresses
				acl_line_words = acl_line.split()
				if acl_line_words[0] == "any" or acl_line_words[0] == "any4":
					acl_dst_cidr.append('0.0.0.0/0')
					#print("destination is any")
					#Could be the end, only remove if there are more items to split
					if len(acl_line_words) >1:
						acl_line = acl_line.split(acl_line_words[0] + ' ',1)[1]
					else:
						acl_line = ''

				elif acl_line_words[0] == "object-group":
					og_network_dst = acl_line_words[1] 
					acl_og_items = list()
					acl_dst_cidr = get_network_og_items(acl_line_words[1], acl_og_items)
					#print("destination OG: " + str(og_network_dst))
					#Could be the end, only remove if there are more items to split
					if len(acl_line_words) >2:
						acl_line = acl_line.split(acl_line_words[1] + ' ',1)[1]
					else:
						acl_line = ''

				elif acl_line_words[0] == "host":
					acl_dst_cidr.append(str(acl_line_words[1] + '/32'))
					#print("destination host(s) ", acl_dst_cidr)
					#Could be the end, only remove if there are more items to split
					if len(acl_line_words) >2:
						acl_line = acl_line.split(acl_line_words[0] + ' ',1)[1]
					else:
						acl_line = ''

				elif is_ipv4(acl_line_words[0]):
					#ACL source is a subnet
					acl_dst_cidr.append(str(acl_line_words[0]) + '/' + str(netmask_to_cidr(acl_line_words[1])))
					#print("destination host(s) ", acl_dst_cidr)
					#Could be the end, only remove if there are more items to split
					if len(acl_line_words) >2:
						acl_line = acl_line.split(acl_line_words[1] + ' ',1)[1]
					else:
						acl_line = ''

				elif acl_line_words[0] == "object":
					acl_object = get_object_item(parse, 'network', str(acl_line_words[1]))
					acl_dst_cidr.append(str(acl_object))
					#print("destination host(s) ", acl_dst_cidr)
					#Could be the end, only remove if there are more items to split
					if len(acl_line_words) >2:
						acl_line = acl_line.split(acl_line_words[0] + ' ',1)[1]
					else:
						acl_line = ''

				else:
					status_update(" NOT FOUND DESTINATION ADDRESS : " + str(acl_line_words[0]) , True, 'warning', debug)
					parsed_acl_lines -= 1
					parsed_unknown_lines += 1
				#If acl_line not ended, possible object0group, port or port range in acl-line
				if acl_line != '':
					#print("restant na destination split: " + str(acl_line))
					acl_line_words = acl_line.split()
					if acl_line_words[0] == "eq":
						if acl_protocol == 'tcp':
							acl_dst_port_tcp.append(replace_port_name_to_number(acl_line_words[1]))
						elif acl_protocol == 'udp':
							acl_dst_port_udp.append(replace_port_name_to_number(acl_line_words[1]))
						elif acl_protocol == 'icmp':
							acl_dst_port_icmp.append(replace_port_name_to_number(acl_line_words[1]))	
						else:
							print(original_acl_line)
							status_update("ERROR! Destination port not combined with protoco list : " + str(acl_protocol) , True, 'critical', debug)

					elif acl_line_words[0] == "range":
						range_start = int(replace_port_name_to_number(acl_line_words[1]))
						range_end = int(replace_port_name_to_number(acl_line_words[2]))
						if (EXTRACT_PORT_RANGES):

							try:
								for i in range(range_start, range_end+1):
									if acl_protocol == 'tcp':
										acl_dst_port_tcp.append(i)
									elif acl_protocol == 'udp':
										acl_dst_port_udp.append(i)
									elif acl_protocol == 'icmp':
										acl_dst_port_icmp.append(i)	
									else:
										if acl_dst_port_protocol != '':
											for item in acl_dst_protocol:
												if item == 'tcp':
													acl_dst_port_tcp.append(i)
												elif item == 'udp':
													acl_dst_port_udp.append(i)
												elif item == 'icmp':
													acl_dst_port_icmp.append(i)	
												else:
													print("ERROR! protocol not found")

										else:			
											print(original_acl_line)
											print(acl_dst_port_protocol)
											status_update("ERROR! Destination port RANGE not combined with protoco list : " + str(acl_protocol) , True, 'critical', debug)
							except:
								if acl_protocol == 'tcp':
									acl_dst_port_tcp.append(str(range_start) +"-"+ str(range_end))
								elif acl_protocol == 'udp':
									acl_dst_port_udp.append(str(range_start) +"-"+ str(range_end))
								elif acl_protocol == 'icmp':
									acl_dst_port_icmp.append(str(range_start) +"-"+ str(range_end))	
								pass
						else:
							if acl_protocol == 'tcp':
								acl_dst_port_tcp.append(str(range_start) +"-"+ str(range_end))
							elif acl_protocol == 'udp':
								acl_dst_port_udp.append(str(range_start) +"-"+ str(range_end))
							elif acl_protocol == 'icmp':
								acl_dst_port_icmp.append(str(range_start) +"-"+ str(range_end))	


					elif acl_line_words[0] == "object-group":
						og_service_name = acl_line_words[1]
						acl_dst_port_tcp, acl_dst_port_udp, acl_dst_port_protocol, acl_dst_port_icmp, sub_og_list = get_service_og_items(og_service_name)
						
						#Could be the end, only remove if there are more items to split
						if len(acl_line_words) >2:
							acl_line = acl_line.split(acl_line_words[1] + ' ',1)[1]
						#else:
						#	acl_line = ''

						#print("destination portrange is " + str(acl_line_words[1]) + " - " + str(acl_line_words[2]))

					elif is_ipv4(acl_line_words[0]):
						#destinaion IP
						acl_dst_cidr.append(str(acl_line_words[0] + '/32'))
						if len(acl_line_words) >1:
							acl_line = acl_line.split(acl_line_words[0] + ' ',1)[1]

					else:
						
						status_update("POSSIBLE END OF ACL LINE NO MATCH FOUND FOR : " + str(acl_line_words[0]) + " on line " + str(original_acl_line) , True, 'critical', debug)
						parsed_acl_lines -= 1			
						parsed_unknown_lines += 1

					#Eventually destination port or port-groups (group-object) same loop as above <<
					if acl_line != '':

						acl_line_words = acl_line.split()
						if acl_line_words[0] == "eq":
							if acl_protocol == 'tcp':
								acl_dst_port_tcp.append(replace_port_name_to_number(acl_line_words[1]))
							elif acl_protocol == 'udp':
								acl_dst_port_udp.append(replace_port_name_to_number(acl_line_words[1]))
							elif acl_protocol == 'icmp':
								acl_dst_port_icmp.append(replace_port_name_to_number(acl_line_words[1]))	
							else:
								print(acl_line)
								print(original_acl_line)
								status_update("ERROR! Destination port not combined with protoco list : " + str(acl_protocol) , True, 'critical', debug)

						elif acl_line_words[0] == "range":
							range_start = int(replace_port_name_to_number(acl_line_words[1]))
							range_end = int(replace_port_name_to_number(acl_line_words[2]))
							if (EXTRACT_PORT_RANGES):

								try:
									for i in range(range_start, range_end+1):
										if acl_protocol == 'tcp':
											acl_dst_port_tcp.append(i)
										elif acl_protocol == 'udp':
											acl_dst_port_udp.append(i)
										elif acl_protocol == 'icmp':
											acl_dst_port_icmp.append(i)	
										else:
											if acl_dst_port_protocol != '':
													for item in acl_dst_protocol:
														if item == 'tcp':
															acl_dst_port_tcp.append(i)
														elif item == 'udp':
															acl_dst_port_udp.append(i)
														elif item == 'icmp':
															acl_dst_port_icmp.append(i)	
														else:
															print("ERROR! protocol not found")

											else:			
												print(original_acl_line)
												print(acl_dst_port_protocol)
												status_update("ERROR! Destination port not combined with protoco list : " + str(acl_protocol) , True, 'critical', debug)
								except:
									if acl_protocol == 'tcp':
										acl_dst_port_tcp.append(str(range_start) +"-"+ str(range_end))
									elif acl_protocol == 'udp':
										acl_dst_port_udp.append(str(range_start) +"-"+ str(range_end))
									elif acl_protocol == 'icmp':
										acl_dst_port_icmp.append(str(range_start) +"-"+ str(range_end))	
									pass
							else:
								if acl_protocol == 'tcp':
									acl_dst_port_tcp.append(str(range_start) +"-"+ str(range_end))
								elif acl_protocol == 'udp':
									acl_dst_port_udp.append(str(range_start) +"-"+ str(range_end))
								elif acl_protocol == 'icmp':
									acl_dst_port_icmp.append(str(range_start) +"-"+ str(range_end))									
						elif acl_line_words[0] == "object-group":
							og_service_name = acl_line_words[1]
							acl_dst_port_tcp, acl_dst_port_udp, acl_dst_port_protocol, acl_dst_port_icmp, sub_og_list = get_service_og_items(og_service_name)
							
							#Could be the end, only remove if there are more items to split
							if len(acl_line_words) >2:
								acl_line = acl_line.split(acl_line_words[1] + ' ',1)[1]
							#else:
							#	acl_line = ''

							#print("destination portrange is " + str(acl_line_words[1]) + " - " + str(acl_line_words[2]))

						elif is_ipv4(acl_line_words[0]):
							#destinaion IP
							acl_dst_cidr.append(str(acl_line_words[0] + '/32'))
							if len(acl_line_words) >1:
								acl_line = acl_line.split(acl_line_words[0] + ' ',1)[1]

						else:
							
							status_update("END OF ACL LINE NO MATCH FOUND FOR : " + str(acl_line_words[0]) , True, 'critical', debug)
							parsed_acl_lines -= 1			
							parsed_unknown_lines += 1

				
				#Building export list
				if (debug) or (SHOW_ACL_EXTRACTION):

					print("ACL_Type : " + str(acl_type))
					print("Protocol : " + str(acl_protocol))
					print("Service object-group : " + str(og_service_name))
					print("Source IPs : " + str(acl_source_cidr))
					print("Destination IPs" + str(acl_dst_cidr))
					print("Protocol allowed : " + str(acl_dst_port_protocol))
					print("Destination ports tcp : " + str(acl_dst_port_tcp))
					print("Destination ports udp : " + str(acl_dst_port_udp))
					print("Destination ports icmp : " + str(acl_dst_port_icmp))
					print("Logging enabled : "  + str(acl_logging))
					print("Loggin severity : " + str(acl_logging_severity))
					print("Line inactive : " + str(acl_inactive))

				if (debug):
					status_update("Number of OG group service : " + str(og_service) + str(key) , True, 'info', debug)
					status_update("Number of OG group network : " + str(og_network) + str(key) , True, 'info', debug)
					status_update("Number of OG group port-oj : " + str(og_port) + str(key) , True, 'info', debug)

				
				
				#Create all possible combinations of sourc - dest - port 
				#if item[u'acl_protocol_og_list'] != '':
				#	#acl_source_destination_port_list = list(itertools.product(source_ips, destination_ips, destination_ports, acl_protocol_items))	
				acl_export_list_tcp = ''
				acl_export_list_udp = ''
				acl_export_list_prot = ''
				acl_export_list_icmp = ''

				acl_export_list_tcp = list(itertools.product(acl_source_cidr, acl_dst_cidr, acl_dst_port_tcp))
				acl_export_list_udp = list(itertools.product(acl_source_cidr, acl_dst_cidr, acl_dst_port_udp))
				acl_export_list_prot = list(itertools.product(acl_source_cidr, acl_dst_cidr, acl_dst_port_protocol))
				acl_export_list_icmp = list(itertools.product(acl_source_cidr, acl_dst_cidr, acl_dst_port_icmp))

				#	acl_source_destination_port_list = list(itertools.product(source_ips, destination_ips, destination_ports))
				acl_line_child = 0
				for source_cidr, destination_cidr, port_number in acl_export_list_tcp:
					acl_line_child += 1
					total_acl_lines += 1
					new_dict_line = {'acl_line_number': acl_line_number, \
						'acl_line_child': acl_line_child, \
						'acl_type': acl_type, \
						'acl_interface': acl_interface, \
						'acl_direction': acl_direction, \
						'acl_name': acl_name, \
						'inactive': acl_inactive, \
						'acl_source_cidr': source_cidr, \
						'acl_source_protocol': 'tcp', \
						'acl_source_port': '', \
						'acl_dst_cidr': destination_cidr, \
						'acl_dst_protocol': 'tcp', \
						'acl_dst_port': port_number, \
						'acl_logging': acl_logging, \
						'acl_interface': acl_interface, \
						'acl_logging_severity': acl_logging_severity, \
						'original_acl_line': original_acl_line \
						}
					#print(new_dict_line)
					acl_line_dict[total_acl_lines] = new_dict_line

					#Update processed item logbook, item processed now
					processed_acl_lines[processed_acl_id].update({'acl_processed': True})
				#UDP LIST
				for source_cidr, destination_cidr, port_number in acl_export_list_udp:
					acl_line_child += 1
					total_acl_lines += 1
					new_dict_line = {'acl_line_number': acl_line_number, \
						'acl_line_child': acl_line_child, \
						'acl_type': acl_type, \
						'acl_interface': acl_interface, \
						'acl_direction': acl_direction, \
						'acl_name': acl_name, \
						'inactive': acl_inactive, \
						'acl_source_cidr': source_cidr, \
						'acl_source_protocol': 'udp', \
						'acl_source_port': '', \
						'acl_dst_cidr': destination_cidr, \
						'acl_dst_protocol': 'udp', \
						'acl_dst_port': port_number, \
						'acl_logging': acl_logging, \
						'acl_interface': acl_interface, \
						'acl_logging_severity': acl_logging_severity, \
						'original_acl_line': original_acl_line \
						}
					#print(new_dict_line)
					acl_line_dict[total_acl_lines] = new_dict_line

					#Update processed item logbook, item processed now
					processed_acl_lines[processed_acl_id].update({'acl_processed': True})

				#ICMP LIST
				for source_cidr, destination_cidr, port_number in acl_export_list_icmp:
					acl_line_child += 1
					total_acl_lines += 1
					new_dict_line = {'acl_line_number': acl_line_number, \
						'acl_line_child': acl_line_child, \
						'acl_type': acl_type, \
						'acl_interface': acl_interface, \
						'acl_direction': acl_direction, \
						'acl_name': acl_name, \
						'inactive': acl_inactive, \
						'acl_source_cidr': source_cidr, \
						'acl_source_protocol': 'icmp', \
						'acl_source_port': '', \
						'acl_dst_cidr': destination_cidr, \
						'acl_dst_protocol': 'icmp', \
						'acl_dst_port': port_number, \
						'acl_logging': acl_logging, \
						'acl_interface': acl_interface, \
						'acl_logging_severity': acl_logging_severity, \
						'original_acl_line': original_acl_line \
						}
					#print(new_dict_line)
					acl_line_dict[total_acl_lines] = new_dict_line

					#Update processed item logbook, item processed now
					processed_acl_lines[processed_acl_id].update({'acl_processed': True})

				#PROTOCOL LIST
				for source_cidr, destination_cidr, protocol in acl_export_list_prot:
					acl_line_child += 1
					total_acl_lines += 1
					new_dict_line = {'acl_line_number': acl_line_number, \
						'acl_line_child': acl_line_child, \
						'acl_type': acl_type, \
						'acl_interface': acl_interface, \
						'acl_direction': acl_direction, \
						'acl_name': acl_name, \
						'inactive': acl_inactive, \
						'acl_source_cidr': source_cidr, \
						'acl_source_protocol': protocol, \
						'acl_source_port': '', \
						'acl_dst_cidr': destination_cidr, \
						'acl_dst_protocol': protocol, \
						'acl_dst_port': '', \
						'acl_logging': acl_logging, \
						'acl_interface': acl_interface, \
						'acl_logging_severity': acl_logging_severity, \
						'original_acl_line': original_acl_line \
						}
					#print("New acl line dict ID " + str(total_acl_lines))
					#print(new_dict_line)
					acl_line_dict[total_acl_lines] = new_dict_line

					#Update processed item logbook, item processed now
					processed_acl_lines[processed_acl_id].update({'acl_processed': True})

			else:
				parsed_unknown_lines = parsed_unknown_lines + 1
				status_update("ERROR! Unkown ACL type!" , True, 'critical', debug)
	return (total_acl_lines, parsed_remark_lines, parsed_acl_lines, parsed_unknown_lines, acl_line_dict, processed_acl_lines)

def export_acl_dict(hostname, export_dict):
	global output_dir
	export_dir = os.path.join(output_dir, '')
	export_file = export_dir + hostname + '-all_acl_lines'
	#print("Start export of ACL for device  " + str(hostname) + " to " + str(export_file))
	#Delete file if exist
	if not os.path.exists(export_dir):
		os.makedirs(export_dir)
	else:
		#Folder exist, remove file if already exist
		try:
			os.remove(export_dir + export_file)
		except OSError:
			pass

	if (EXPORT_TYPE == 'excel'):
		writer = pd.ExcelWriter(export_file + '.xlxs')
		df = pd.DataFrame
		for key, value in export_dict.items():
			status_update("Export to Excel  : " + str(hostname) + " - acl : " + str(key) , True, 'info', debug)
			if (EXPORT_TO_TABS):
				#pprint(value)
				df = pd.DataFrame.from_dict(value, orient='index')
				df.to_excel(writer,key)
			else:
				df2 = pd.DataFrame.from_dict(value, orient='index')
				print("Export to single tab, combine all ACLs")
				#df.insert(0, 'Name', 'abc')

		writer.save()
	else:
		csv_columns = ['acl_line_number', 'acl_line_child', 'acl_interface', 'acl_direction', 'acl_name', \
				'inactive', 'acl_type', \
				'acl_source_cidr', 'acl_dst_cidr', 'acl_dst_port', 'acl_protocol', \
				'dst_interface', 'dst_next_hop', 'dst_next_hop_prio', \
				'original_acl_line']
		with open(export_file + '.csv', open_csv_writemode) as csv_file:
			writer = csv.writer(csv_file)
			writer.writerow(csv_columns)
			
			# Temporary
			dst_next_hop_intf = ''
			dst_next_hop_ip = ''
			dst_next_hop_prio = ''

			for key, value in export_dict.items():
				print(key)
				for key2, item in value.items():

					#print(item)
					new_csv_row = (int(item['acl_line_number']), item['acl_line_child'], item['acl_interface'], item['acl_direction'], key, \
						item['inactive'], item['acl_type'],  \
						item['acl_source_cidr'], item['acl_dst_cidr'], item['acl_dst_port'], item['acl_dst_protocol'], \
						dst_next_hop_intf, dst_next_hop_ip, dst_next_hop_prio, \
						item['original_acl_line'])
					if (debug_export):
						print("NEW DICT TO CSV LINE: "),
						print(new_csv_row)
					writer.writerow(new_csv_row)


def extract_asa_config_file(parse):


	#Get hostname - needed for printout and export
	global hostname
	hostname = ''
	hostname = get_hostname(parse)


	# Create global dict with all acl lines
	global extracted_acl_lines
	extracted_acl_lines = dict()


	global export_dict 							# Dict save every ACL internal dict, at the end this will be used for export to excel file, every ACL to new tab
	export_dict = dict()
	# Get insterfaces
	all_intfs = intf_acl_to_dict(parse)
	total_acl_lines = 0
	#Loop trough interfaces and return extracted ACL lines
	for key, value in all_intfs.items():
		#print(key, value)
		
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
			status_update("Start extraction for " + str(acl_name) , False, 'info', debug)
			total_acl_lines, parsed_remark_lines, parsed_acl_lines, parsed_unknown_lines, acl_lines_this_acl,  processed_acl_lines = get_acl_lines(parse, total_acl_lines, acl_name, acl_interface, acl_direction)
			export_dict[acl_name] = acl_lines_this_acl
			

		print("*" * 40)
		print(" This ACL Remarks :" + str(parsed_remark_lines))
		print(" This ACL lines : " + str(parsed_acl_lines))
		print(" This ACL Unknown lines : " + str(parsed_unknown_lines))
		print("*" * 40)
		print(" Total ACL Lines :" + str(total_acl_lines))
		print("*" * 80)

	export_acl_dict(hostname, export_dict)

def main():
	
	# Get al ACL_input files
	config_files = dict()
	config_files = read_config_files(input_dir)
	#print(config_files)

	# Create global dict with portname to number, only if enabled for extraction
	global portDict
	portDict = dict()
	portDict_CSV = './external/cisco_asa_pname-pnum.csv'
	with open(portDict_CSV, mode='r') as portDict_CSV_file:
		reader = csv.reader(portDict_CSV_file)
		for row in reader:
			#pprint(row)
			portDict[row[0]] = row[1]		

	status_update("Start" , True, 'info', debug)
	# Loop trough config_files
	for key, value in config_files.items():
		# Read in config
		status_update("Read config file : " + str(value[u'file_name']) , True, 'info', True)
		parse = parseconfig(value['file_path'])
		#pprint(parse)	
		global og_dict
		og_dict = dict()
		og_dict = create_og_dict(parse)
		
		#print("Extracted OG_DICT")
		#pprint(og_dict)
		# Only READ IN ONCE! = Global, Reverced = True
		# Need import of __routing__.py
		global network_routes	
		network_routes = dict()
		network_routes = get_network_routes(parse, True)			
	
		#Extract ACL lines
		extraction = extract_asa_config_file(parse)



if __name__ == "__main__":
	main()