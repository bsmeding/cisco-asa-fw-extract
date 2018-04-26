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

Run ./split_acl.py to:

* Check all incoming and outgoing access-lists (run trough interfaces)
* For every ACL, get content and extract line-by-line to new CSV file
* Optionally extract compact lines with object-groups to single lines so you can filter on source - destination
* Optionally add information of destination IP/subnet routing next hop/outgoing interface


Note
====

Current version is in very beta state, so please check manually correct exports!

I assume that acl_protocol object-groups (at beginning of acl line) will handle only protocol and _destination_ ports, no source port OG's are supported