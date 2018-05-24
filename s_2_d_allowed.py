#!/usr/bin/env python
from __future__ import unicode_literals

#import ipaddr											# Used for IP - Route match
#from __routing__ import *							# Used for nexthop information
from collections import OrderedDict
import csv
from pprint import pprint

"""
Import file for Cisco ASA config normalization
This file holds the functions to export all source to destination allowed rules

# Import CSV
	- subnet to name mapping : first column is subnet (cidr format), second column is Network Name
	- ACL extraction (the export file of split_acl.py)			In later stadium this can be integrated to each other

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
input_csv_acl_lines = "./output/INTERCONNECT-all_acl_lines.csv"
input_destination_MenM_export = "./input/BlauwDMZ-primair1.csv"


def read_csv_acl_lines(inputfile):
	"""
	function to read in CSV file and return dict with first row as dict keys
	Here in use by previously exported file other function: split_acl.py
	"""
	count = 0
	with open(inputfile, 'rb') as infile:

		reader = csv.DictReader(infile)
		for row in reader:
			#pprint(row)
			count += 1
			acl_lines[count] = row
	return acl_lines


def read_csv_menm_export(inputfile):
	"""
	function to read in the exported file of Men and Mice and return dictionary of ACTIVE ips
	"""
	with open(inputfile, mode='r') as infile:
		reader = csv.reader(infile)
		for rows in reader:
			if rows[1] != 'Free':
				new_dict_line = {'assigned': rows[1], 'host': rows[2], 'description': rows[3]}
				destination_IPs[rows[0]] = new_dict_line	
	return destination_IPs

def find_matching_destination_lines(find_IP):
	"""

	Used the global dict 'acl_lines' for matching. These dict must read in an export file from split_acl
	"""
	matched_acl_dict = dict()
	for key, value in acl_lines.iteritems():
		#pprint(value)
		if value['acl_dst_host_id'] == find_IP:
			matching_acl_line = value['acl_line_number']

			matched_acl_dict[matching_acl_line] = value
	return matched_acl_dict

def main():
	
	# Read in export CSV from split_acl.py set to global dictionary
	global acl_lines
	acl_lines = dict()
	print("read in ACL file: " + input_csv_acl_lines)
	acl_lines = read_csv_acl_lines(input_csv_acl_lines)

	# Read in destination IP addresses, based on export from Men and Mice
	global destination_IPs
	destination_IPs = dict()
	print("read in destination IP export from Men and Mice: " + input_destination_MenM_export)
	destination_IPs = read_csv_menm_export(input_destination_MenM_export)
	#pprint(destination_IPs)


	# Match destination IP's on ACL destination IPs (or subnet where destination IP have a match on)
	###### <<<<< CHECK SUBNET MATCHING!!!!!!
	destination_IPs = OrderedDict(sorted(destination_IPs.items()))
	#for key, value in destination_IPs.items():
	#	print(key)
	matched_lines = find_matching_destination_lines('172.20.12.36')
	pprint(matched_lines)




if __name__ == "__main__":
	main()
