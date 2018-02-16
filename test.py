from module import *

if len(sys.argv) == 3:
	range_file = sys.argv[1]
	pass_file = sys.argv[2]
else:
	print sys.argv
	print "\n* Incorrect number of arguments!"
	sys.exit()

ips, masks = ip_is_valid(range_file)
pass_list = pass_is_valid(pass_file)

#print ips, masks

devices = []

for index, ip in enumerate(ips):
	net = get_net_addr(ip, masks[index])
	#print net
	hosts = get_all_net_hosts(net, masks[index])
	#print ip
	#print net
	tmp_dict = {"net_addr": net, "hosts": hosts}
	devices.append(tmp_dict)


coffee = r"""                                /\
                          /\   / /
                         / /   \ \
                         \ \    \ \
                          \ \    \ \
                          / /    / /
                         / /     \/
                         \/
                   ***********************
                ***                       ***
              **                             **
              ****                         ***** ******
              ***********************************      ** 
              *********************************        **
               *******************************        **
                *****************************     ****
                 *********************************
                  **************************
                   ***********************
                      ***************** 
                         ***********
		"""

print Fore.GREEN + Style.BRIGHT + "\n* Cheking ip connectivity....Please wait....\n"

for i in devices:	
	create_ping_threads(i["hosts"])



#print "\n Available ips: "
#pprint(available_ips)
chech_loc_ifaces()

#unq_ip = available_ips
#print "unqueried ips"
#pprint(unq_ip)

print Fore.GREEN + Style.BRIGHT + "\n* IP addresses are found!"
print "* I will create SSH connections to devices and gather all the necessary information for you!"
print "* Please wait....It might take up to 2 minutes"
print "* Here, drink coffee:)\n"
print Fore.WHITE + Style.BRIGHT + coffee


while True:
	if len(available_ips) == 0:
		break
	else:
		ip = available_ips[0]
		client = open_ssh_conn(ip, pass_list)
		if client:
			gather_info(client)
			#print "management ips: " + str(dev_manage_info)
			#print "unqueried ips : " + str(available_ips)
		else:
			available_ips.remove(ip)
			#print "management ips: " + str(dev_manage_info)
			#print "unqueried ips : " + str(available_ips)
		
print Fore.GREEN + Style.BRIGHT + "\n* Done!"

#print_iface_info()
#write_iface_info()

write_cred_csv()


print_module_info()
write_module_info()

print_version_info()
write_ver_info()
#print "unqueried ips"
#pprint(unq_ip)

#print "\nCDP info list"
#pprint(dev_cdp_list)

#pprint(neighborship_dict)
draw_topology()
