Cisco ASA config extract
========================




Requirements
============

Python modules:
* pip3 install ipaddr
* pip3 install CiscoConfParse
* pip3 install pandas


Example
=======
Make file executable: chmod +x split_acl.py

Edit the file with the config file name and the output file + directory (NOTE: output dir will be deleted and renewed at running!)
* input_config_file = "ciscoconfig.conf" 
* output_csv_file = "acl_seperated.csv"   << Not implemented yet
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
* For every ACL, get content and extract line-by-line
* Extract compact lines with object-groups to single lines so you can filter on source - destination
* Optionally add information of destination IP/subnet routing next hop/outgoing interface


ToDo
====
* Create input dir, loop trough all files (so no input file must be edited in the split_acl file)
* Add next hop interface
* Change port names to numbers (from input CSV)
* Seperate file for object-group functions, this file can be run seperataly to extraxct object groups and check if OG is in use)
* create function where input is, source - destination and check in output file what is allowed (hits on ACL lines)


Note
====

Current version is in very beta state, so please check manually correct exports!

I assume that acl_protocol object-groups (at beginning of acl line) will handle only protocol and _destination_ ports, no source port OG's are supported