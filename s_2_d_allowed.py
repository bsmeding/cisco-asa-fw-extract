import ipaddr											# Used for IP - Route match
from ___routing___	import *							# Used for nexthop information
from collections import OrderedDict


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

