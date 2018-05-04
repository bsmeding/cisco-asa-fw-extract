#!/usr/bin/env python
from __future__ import unicode_literals

#import ipaddr											# Used for IP - Route match
#from __routing__ import *							# Used for nexthop information
#from collections import OrderedDict
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
input_csv_acl_lines = "./output/INTERCONNECT-all_acl_lines_OLD.csv"

def main():
	
	print("Read in ACL csv file to global dictionary")
	# Read in export CSV from split_acl.py set to global dictionary
	acl_lines = dict()
	print(input_csv_acl_lines)
	count = 0
	with open(input_csv_acl_lines, 'rb') as infile:

		reader = csv.DictReader(infile)
		for row in reader:
			#pprint(row)
			count += 1
			acl_lines[count] = row
	print(acl_lines)
if __name__ == "__main__":
	main()
