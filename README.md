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

Create folder:
./output
./log
./conf_input/

puth cisco ASA config files in ./conf_input/

run script, for every file there will be a new Excel file in './acl_output/ with a tab for every ACL found.


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
