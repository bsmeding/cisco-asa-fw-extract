Cisco ASA config extract
========================




Requirements
============

Python modules:
* pip install ipaddr
* pip install CiscoConfParse


Example
=======
Make file executable: chmod +x split_acl.py

Edit the file with the config file name and the output file + directory (NOTE: output dir will be deleted and renewed at running!)
* input_config_file = "ciscoconfig.conf" 
* output_csv_file = "acl_seperated.csv"
* output_dir = 'output'

Edit output variables:
* PRINT_REMARKS = False				# True for print to screen, False no print to screen
* PRINT_LINES = False 				# Print line info
* PRINT_FULL_OUTPUT = False 		# Print full extract info (debug)
* EXPORT_REMARKS = False 			# Skip the remark lines in export output
* FLATTEN_NESTED_LISTS = True		# True if the output of nested lists must be extracted to one list 
* SKIP_INACTIVE = True				# True to skip lines that are inactie (last word of ACL line)
* SKIP_TIME_EXCEEDED = False		# Skip rules with time-ranges that have passed by
* EXTEND_PORT_RANGES = True 		# When True the ranges will be added seperataly, from begin to end range port. Other it will be printed as <port_start>-<port_end>

Run ./split_acl.py to:

* Check all incoming and outgoing access-lists (run trough interfaces)
* For every ACL, get content and extract line-by-line to new CSV file
* Optionally extract compact lines with object-groups to single lines so you can filter on source - destination
* Optionally add information of destination IP/subnet routing next hop/outgoing interface


Note
====

Current version is in very beta state, so please check manually correct exports!

I assume that acl_protocol object-groups (at beginning of acl line) will handle only protocol and _destination_ ports, no source port OG's are supported