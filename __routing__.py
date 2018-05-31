import ipaddr											# Used for IP - Route match
from ___cidr_convert___	import netmask_to_cidr				# Convert CIDR to Network address and reverse
from collections import OrderedDict


"""
Import file for Cisco ASA config normalization

This file holds the functions for Routing entries




"""
def get_network_routes(parse, ReturnReversed):
	"""
	Function that will return a dict with network routes (host_id, subnet_id, next_hop, exit_interface)
	"""
	dict_network_routes = dict()
	for network_route in parse.find_objects(r'route\s'):
		
		cfg_line_number = network_route.linenum 	# Dict identification
		#Split routes to Dict
		network_route_items = network_route.text.split()
		network_route_items_words = len(network_route_items)
		if network_route_items_words == 6:
			#Split line to dict
			network_route_host_id = network_route_items[2]
			network_route_subnet_id = network_route_items[3]
			network_route_next_hop = network_route_items[4]
			network_route_exit_intf = network_route_items[1]
			network_route_priority =  network_route_items[5]
			#Change host_id and subnet_id to CIDS mask (need to import file ___cidr_convert___)
			network_route_subnet_cidr = str(netmask_to_cidr(network_route_items[3]))
			# Add to dictionary
			new_acl_dict_line = {'network_route_host_id': network_route_host_id, 'network_route_subnet_id': network_route_subnet_id, 'network_route_subnet_cidr': network_route_subnet_cidr, \
				'network_route_next_hop': network_route_next_hop, 'network_route_exit_intf': network_route_exit_intf, 'network_route_priority': network_route_priority}
			dict_network_routes[cfg_line_number] = new_acl_dict_line
		else:
			print("ERROR! Unsupported route table entry : " + network_route.text)
	
	#Order the returning dict		
	#dict_network_routes = OrderedDict(sorted(dict_network_routes.items(), key=lambda kv: kv[1]['network_route_subnet_cidr']))
	dict_network_routes = OrderedDict(sorted(dict_network_routes.items(), key=lambda kv: kv[1]['network_route_subnet_cidr'], reverse=ReturnReversed))


	return dict_network_routes

def get_ip_next_hop(network_routes, ip_cidr):
	"""
	Function that will return, ip_next_hop, outgoing interface, route_prio
	"""
	for key, value in network_routes.items():
		route_cidr = value[u'network_route_host_id'] + "/" + value[u'network_route_subnet_cidr']
		network_route_exit_intf = value[u'network_route_exit_intf']
		network_route_next_hop = value[u'network_route_next_hop']
		network_route_priority = value[u'network_route_priority']
		#print(i, route_cidr)
		#for j in iplist:

		try:
			ip_source = ipaddr.IPNetwork(ip_cidr)
			ip_route = ipaddr.IPNetwork(route_cidr)

			#print(ip_source)
			#print(ip_route)
			if ip_source.overlaps(ip_route):
				#print("MATCH : " + str(ip_source) + " ==> " + str(ip_route) + " next hop : " + network_route_next_hop + " ( exit interface : " + network_route_exit_intf + " )")
				return (network_route_next_hop, network_route_exit_intf, network_route_priority)
				break 		# Only first match is needed. Route order must be ordered by route_cids_subnet, Reversed!
		except:
			pass
			
