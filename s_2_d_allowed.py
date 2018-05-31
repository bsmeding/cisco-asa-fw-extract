#!/usr/bin/env python
from __future__ import unicode_literals
import sys
import os									# Used for IP - Route match
import re
from ___cidr_convert___ import *
from collections import OrderedDict
import csv
from pprint import pprint

from netaddr import IPNetwork, IPAddress


debug = False
FIND_DIRECT_LINES_ONLY = False 			# When enabled, only direct host matches are exported, only also subnet check will be performed



#Check Python version
if sys.version_info[0] >= 3:
	python3 = True
	open_csv_writemode = 'w'
	open_csv_readmode = 'r'
else:
	python3 = False
	open_csv_writemode = 'wb'
	open_csv_readmode = 'rb'	



"""
Import file for Cisco ASA config normalization
This file holds the functions to export all source to destination allowed rules

# Import CSV
	- subnet to name mapping : first column is subnet (cidr format), second column is Network Name
	- ACL extraction (the export file of split_acl.py)			In later stadium this can be integrated to each other

ToDo:
- check if IP is in subnet match (now only direct/host match)
- Add this to initial split_acl script so it will be one programm

"""
input_csv_acl_lines = "./output/DEVICENAME-all_acl_lines.csv"
input_destination_MenM_export = "./input/MenM-Export.csv"

#Generate output file, based on input
# >>> NEED TO CHANGE ! : MUST BE : MATCHES_OF_import_file_name_and_destination_file_name.csv
new_csv_file = strip_csv_from_filename(input_destination_MenM_export)
new_csv_file = new_csv_file + "_with_acl_lines.csv"


def read_csv_acl_lines(inputfile):
	"""
	function to read in CSV file and return dict with first row as dict keys
	Here in use by previously exported file other function: split_acl.py
	"""
	count = 0

	with open(inputfile, open_csv_readmode) as infile:
		reader = csv.reader(infile)
		next(reader, None)  # skip the headers
		#reader = csv.DictReader(infile)
		#for row in reader:
		
		for row in reader:
			# process each row
			#writer.writerow(row)
			#pprint(row)
			count += 1
			acl_lines[count] = row
	return acl_lines


def read_csv_menm_export(inputfile):
	"""
	function to read in the exported file of Men and Mice and return dictionary of ACTIVE ips
	De csv consists of 4 columns (without column names on first row)
	cel1 : IP address
	cel2 : IP address issigend or free
	cel3 : hostname
	cel4 : description
	CHANGE THIS IMPORT ROW WHEN NEEDED, BUT KEEP THIS FORMAT FOR THE EXPORT DICT
	"""
	with open(inputfile, mode=open_csv_readmode) as infile:
		reader = csv.reader(infile)
		for rows in reader:
			if rows[1] != 'Free':
				new_dict_line = {'assigned': rows[1], 'host': rows[2], 'description': rows[3]}
				destination_IPs[rows[0]] = new_dict_line	
	return destination_IPs

def strip_csv_from_filename(inputfile):
	"""
	Function to return the file name, that is used for the new export file name
	Strip .csv from the end
	#import os
	"""
	import os
	filename, file_extension = os.path.splitext(inputfile)
	return filename

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

def find_matching_destination_lines(find_IP):
	"""

	Used the global dict 'acl_lines' for matching. These dict must read in an export file from split_acl
	"""
	matched_acl_dict = dict()
	matched_lines = 0
	if python3 == True:
		for key, value in acl_lines.items():
			
			#pprint(value)
			#if value['acl_dst_host_id'] == find_IP:
			if value[10] == find_IP:
				matched_lines += 1
				#print("match line : " + value[0] + " match# : ", matched_lines)
				matching_acl_line = value[0]
				matched_acl_dict[matched_lines] = value
	else:
		for key, value in acl_lines.iteritems():
			#pprint(value)
			if value[11] == '255.255.255.255' and (value[10] == find_IP):
				#Host match
				matched_lines += 1
				matching_acl_line = value[0]
				matched_acl_dict[matched_lines] = value
			elif is_ipv4(value[11]) and value[11] != '255.255.255.255' and is_ipv4(find_IP) and FIND_DIRECT_LINES_ONLY == False:
				#Try match on subnet, first set IP to CIDR
				acl_dst_cidr = value[10] + "/" + str(netmask_to_cidr(value[11]))
				if IPAddress(find_IP) in IPNetwork(acl_dst_cidr):
					#print(" CHECK IP " + find_IP + " ON NETWORK : " + acl_dst_cidr)
					matched_lines += 1
					matching_acl_line = value[0]
					matched_acl_dict[matched_lines] = value					
	return matched_acl_dict

def main():
	
	# Read in export CSV from split_acl.py set to global dictionary
	global acl_lines
	acl_lines = dict()
	print("read in ACL file: " + input_csv_acl_lines)
	acl_lines = read_csv_acl_lines(input_csv_acl_lines)
	#pprint(acl_lines)

	# Read in destination IP addresses, based on export from Men and Mice
	global destination_IPs
	destination_IPs = dict()
	print("read in destination IP export from Men and Mice: " + input_destination_MenM_export)
	if (debug):
		new_dict_line = {'assigned': 'Assigned', 'host': 'debug_host', 'description': '**no_desc_in_debug**'}
		destination_IPs['172.20.12.36'] = new_dict_line	
	else:
		destination_IPs = read_csv_menm_export(input_destination_MenM_export)




	# Match destination IP's on ACL destination IPs (or subnet where destination IP have a match on)
	###### <<<<< CHECK SUBNET MATCHING!!!!!!
	#destination_IPs = OrderedDict(sorted(destination_IPs.items()))

	print("export to: " + new_csv_file)

	print("start matching lines...")
	#Add three colums (host, ip, desc) to existing export of split_acl
	csv_columns = ['host','ip','description', \
				'acl_line_number', 'acl_line_child', 'acl_interface', 'acl_direction', 'acl_name', \
				'inactive', 'acl_type', 'acl_action', \
				'acl_source_host_id', 'acl_source_host_sn', 'acl_dst_host_id', 'acl_dst_host_sn', 'acl_dst_port', 'acl_protocol', \
				'dst_interface', 'dst_next_hop', 'dst_next_hop_prio', \
				'original_acl_line']

	export_dict = dict()
	export_dict_rows = 0
	str_hostname = ''
	str_ipaddress = ''
	str_desc = ''
	with open(new_csv_file, open_csv_writemode) as csv_file:
		writer = csv.writer(csv_file)
		writer.writerow(csv_columns)	
		# VERY COMPLEX NOW, CHECK IF THIS CAN BE BETTER ACCOMPLISHED!
		#overwrite for test

		for key, value in destination_IPs.items():
			# Set IP host to variables
			#print(key)
			str_hostname = str(value[u'host'])
			str_ipaddress = str(key)
			str_desc = str(value[u'description'])
			#FInd matching ACL lines for ip
			matched_lines = find_matching_destination_lines(str_ipaddress)
			#pprint(matched_lines)
			for key, value in matched_lines.items():
				export_dict_rows += 1
				new_csv_row = (str_hostname, str_ipaddress, str_desc, \
					value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8], \
					value[9], value[10], value[11], value[12], value[13], value[14], value[15], value[16], value[17]) 
				#print(new_csv_row)
				writer.writerow(new_csv_row)

	#Building new CSV

	#pprint(export_dict)


if __name__ == "__main__":
	main()
