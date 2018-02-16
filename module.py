import sys
import re
import os
import subprocess
import time
import threading
import socket

ip_addr_pattern = re.compile("^(((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\/(3[0-2]|2\d|1\d|\d))(\s+\#.*|\s*)?$")
#start_line_pattern = re.compile("^\s*#.*$")

try:
	from colorama import init, deinit, Fore, Style
except ImportError:
	print "\n* Module colorama needs to be installed on your system."
	print "* Download it from: https://pypi.python.org/pypi/colorama\n"
	sys.exit()

#Initializing colorama
init()

try:
	import netifaces
except ImportError:
	print Fore.RED + Style.BRIGHT + "\n* Module netifaces needs to be installed on your system."
	print "* Download it from: https://pypi.python.org/pypi/netifaces\n" + Fore.WHITE + Style.BRIGHT
	sys.exit()


try:
    import matplotlib.pyplot as matp

except ImportError:
    print Fore.RED + Style.BRIGHT + "\n* Module matplotlib needs to be installed on your system."
    print "* Download it from: https://pypi.python.org/pypi/matplotlib\n" + Fore.WHITE + Style.BRIGHT
    sys.exit()

try:
	import ipaddress
except ImportError:
	print Fore.RED + Style.BRIGHT + "\n* Module ipaddresse needs to be installed on your system."
	print "* Download it from: https://pypi.python.org/pypi/ipaddress\n" + Fore.WHITE + Style.BRIGHT
	sys.exit()

try:    
    import networkx as nx

except ImportError:
    print Fore.RED + Style.BRIGHT + "\n* Module networkx needs to be installed on your system."
    print "* Download it from: https://pypi.python.org/pypi/networkx"
    print "* You should also install decorator: https://pypi.python.org/pypi/decorator\n" + Fore.WHITE + Style.BRIGHT
    sys.exit()

try:
	from pprint import pprint
except ImportError as err:
	print Fore.RED + Style.BRIGHT + "\n* Problem: " + Fore.YELLOW + str(err)
	print Fore.RED + Style.BRIGHT + "* Module pprint needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/pprint" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	import textfsm
except ImportError as err:
	print Fore.RED + Style.BRIGHT + "\n* Problem: " + Fore.YELLOW + str(err)
	print Fore.RED + Style.BRIGHT + "* Module textfsm needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/textfsm" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()


try:
	import paramiko
except ImportError as err:
	print Fore.RED + Style.BRIGHT + "\n* Problem: " + Fore.YELLOW + str(err)
	print Fore.RED + Style.BRIGHT + "* Module paramiko needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/paramiko" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()


#Create all the necessary variables

#List of available ips
available_ips = []

#########################################
#List (of dictionaries) of management information
dev_manage_info = []
#########################################

#List with cdp information
dev_cdp_list = []

#List with general information about each device (list of dictionaries) "show version" command
dev_ver_info = []


#DICTIONARIES
#Module information for each device (dictionary(key = hostname) of lists of dictionaries(each module))
dev_module_info = {}

#For topology generation
neighborship_dict = {}

#Interface information for each device (dict(key = hostname) of lists of dictionaries(each interface))
dev_iface_info = {}


def open_ssh_conn(ip, pswd_list):
	"""Documentation string for open_ssh_conn function"""

	ssh_check = False

	username = "admin"

	global dev_manage 
	dev_manage = {}

	for pswd in pswd_list:
		try:
			ssh_client = paramiko.SSHClient()
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			a = ssh_client.connect(ip, username = username, password = pswd)
			if a == None:
				ssh_check = True
				break
		except paramiko.AuthenticationException:
			ssh_client.close()
			#print Fore.RED + Style.BRIGHT + "\n* Invalid SSH password --> " + Fore.YELLOW + Style.BRIGHT + pswd
			#print Fore.RED + Style.BRIGHT + "\n* Please check the file."
			#print Fore.WHITE + Style.BRIGHT + "\n"
			continue
		except paramiko.ssh_exception.NoValidConnectionsError:
			ssh_check = False
			print Fore.RED + Style.BRIGHT + "\n Too many vty connections to device --> " + ip
			print Fore.WHITE + Style.BRIGHT + "\n"
			break
		except socket.error as err:
			ssh_check = False
			print Fore.RED + Style.BRIGHT + "*\n Error: " + str(err)
			print Fore.WHITE + Style.BRIGHT + "\n"
			break

	if ssh_check == True:
		dev_manage["username"] = username
		dev_manage["password"] = pswd
		dev_manage["manage_ip"] = ip
		return ssh_client
	else:
		#print "\n* Password is not found for a device with ip  " + Fore.YELLOW + Style.BRIGHT + ip
		#print Fore.WHITE + Style.BRIGHT + "\n"
		return False


def gather_info(ssh_client):
	"""Docs"""

	conn =  ssh_client.invoke_shell()

	conn.send("terminal length 0\n")
	time.sleep(1)

	conn.send("show ip interface brief\n")
	time.sleep(1)
	conn.send("show running-config | include hostname\n")
	time.sleep(1)
	conn.send("show diag\n")
	time.sleep(1)
	conn.send("show cdp neighbors detail\n")
	time.sleep(1)
	conn.send("show interfaces\n")
	time.sleep(2)
	conn.send("show version\n")
	time.sleep(1)
	output = conn.recv(50000)

	#print output

	dev_hostname = re.search(r"hostname (\S+)\s*", output)
	if dev_hostname != None:
		hostname = dev_hostname.group(1)
		#print hostname

	#Create a template object for "show ip int brief" command
	sh_ip_int_b = textfsm.TextFSM(open(r"./templates/sh_ip_int_b.textfsm"))
	sh_ip_int_b_res = sh_ip_int_b.ParseText(output)
	#pprint(sh_ip_int_b_res)

	#Create a dictionary with hostname and management ip) and add it to the list dev_ips
	dev_manage["hostname"] = hostname
	dev_manage_info.append(dev_manage)

	#Create a template object for "show interfaces" command
	sh_ifaces = textfsm.TextFSM(open(r"./templates/sh_interfaces.textfsm"))
	sh_ifaces_res = sh_ifaces.ParseText(output)

	#Template list for iface_dict dictionary
	ifaces_temp = ["iface", "phy_st", "prot_st", "description", "ip_addr", "mtu", "bandwidth"]

	ifaces = []
	for value in sh_ifaces_res:
		iface_dict = {key:value[index] for index, key in enumerate(ifaces_temp)}
		ifaces.append(iface_dict)

	dev_iface_info[hostname] = ifaces

	#Create a template object for "show diag" command(search for adapter modules)
	sh_diag_ad = textfsm.TextFSM(open(r"./templates/sh_diag_slots.textfsm"))
	sh_diag_ad_res = sh_diag_ad.ParseText(output)

	#Template list for ad_modules dictionary
	ad_mod_temp = ["slot_no", "module_name", "port_no", "status", "insert_time", "serial_no", "hard_rev", "pid"]

	adapter_modules = []
	#Create a dictionary
	for value in sh_diag_ad_res:
		ad_modules = {key:value[index] for index, key in enumerate(ad_mod_temp)}
		adapter_modules.append(ad_modules)


	#Create a template object for "show diag" command(search for wic modules)
	sh_diag_wic = textfsm.TextFSM(open(r"./templates/sh_diag_wics.textfsm"))
	sh_diag_wic_res = sh_diag_wic.ParseText(output)

	#Template list for w_modules dictionary
	wic_mod_temp = ["slot_no", "module_name", "hard_rev", "serial_no", "pid"]

	wic_modules = []
	#Create dictionary
	for value in sh_diag_wic_res:
		w_modules = {key:value[index] for index, key in enumerate(wic_mod_temp)}
		wic_modules.append(w_modules)

	dev_module_info[hostname] = [adapter_modules, wic_modules]


	#Collecting cdp information
	#Create a template obeject for "show cdp neighbors detail" command
	sh_cdp_nbr_d = textfsm.TextFSM(open(r"./templates/sh_cdp_nbr_d.textfsm"))
	sh_cdp_nbr_d_res = sh_cdp_nbr_d.ParseText(output)

	#Template list for cdp_nbr doctionary
	cdp_nbr_temp = ["nbr_id", "nbr_domain", "nbr_ip", "host_iface", "nbr_iface"]

	#Create dictionary
	for value in sh_cdp_nbr_d_res:
		cdp_nbr = {key:value[index] for index, key in enumerate(cdp_nbr_temp)}
		cdp_nbr["host_id"] = hostname
		dev_cdp_list.append(cdp_nbr)



	sh_ver_temp = ["sys_type", "hard_platform", "soft_name", "soft_ver", "hostname", "uptime",
					"image", "proc_type", "proc_freq", "ram_mem", "shared_mem", "nvram", "conf_reg"]

	sh_ver = textfsm.TextFSM(open(r"./templates/sh_ver.textfsm"))
	sh_ver_res = sh_ver.ParseText(output)



	sh_ver_dict = {key:sh_ver_res[0][index] for index, key in enumerate(sh_ver_temp)}

	eos = "No EoL informatiom found for the software"
	last_day_of_sup = "No EoL informatiom found for the software"
	eol = "No EoL informatiom found for the software"
	#Find out EoS, Last day of support and EoL for the device
	with open(r"./sources/dev_eol.csv") as dev_eol_file:
		dev_eol_file.seek(0)
		for line in dev_eol_file:
			line_l = line.split(",")
			if sh_ver_dict["hard_platform"] == line_l[0]:
				if sh_ver_dict["soft_ver"] == line_l[1]:
					eos = line_l[2]
					last_day_of_sup = line_l[3]
					eol = line_l[4]
					break

	sh_ver_dict["eos"] = eos
	sh_ver_dict["last_day_of_sup"] = last_day_of_sup
	sh_ver_dict["eol"] = eol


	uptime_value_list = sh_ver_dict["uptime"].split(", ")
	#Getting the device uptime in seconds
	y_sec = 0
	w_sec = 0
	d_sec = 0
	h_sec = 0
	m_sec = 0

	for i in uptime_value_list:
		if "year" in i:
			y_sec = int(i.split(" ")[0]) * 31449600
		elif "week" in i:
			w_sec = int(i.split(" ")[0]) * 604800
		elif "day" in i:
			d_sec = int(i.split(" ")[0]) * 86400
		elif "hour" in i:
			h_sec = int(i.split(" ")[0]) * 3600
		elif "minute" in i:
			m_sec = int(i.split(" ")[0]) * 60

	uptime = y_sec + w_sec + d_sec + h_sec + m_sec
	sh_ver_dict["uptime"] = str(uptime)
	dev_ver_info.append(sh_ver_dict)

	#Create a dictionary for topology generation
	for each_dict in dev_cdp_list:
		edge_tuple = (each_dict["host_id"], each_dict["nbr_id"])
		neighborship_dict[edge_tuple] = (each_dict["nbr_iface"], each_dict["nbr_ip"])


	#Find out unqueried ip addresses (remove queried ip addresses from the available_ips list)
	for line in sh_ip_int_b_res:
		nbr_ip = line[1]
		#print "ip = " + nbr_ip
		if nbr_ip in available_ips:
			available_ips.remove(nbr_ip)

	ssh_client.close()


def ip_is_valid(file):
	"""Documentation string for ip_is_valid function"""
	ip_list = []
	mask_list = []
	check = False

	while True:
		try:
			with open(file) as myfile:
				myfile.seek(0)

				if not myfile.read(1):
					print Fore.RED + Style.BRIGHT + "* File " + Fore.YELLOW + file + Fore.RED + Style.BRIGHT + " is empty!"
					print "* Please verify your file!"
					sys.exit()

				myfile.seek(0)
				data = myfile.readlines()
				#pprint(data)

				#Remove duplicate lines(if they exist)
				data_s = set(data)
				#pprint(data_s)

				data = list(data_s)
				#pprint(data)

				count = 0
				for line in data:
					count += 1
					#Empty line
					if line == "\n" and ip_addr_pattern.search(line) == None:
						continue
					elif ip_addr_pattern.search(line) != None:
						entry = ip_addr_pattern.search(line).group(1)
						ip = entry.split("/")[0]
						mask = entry.split("/")[1].rstrip()
						if ip == get_net_addr(ip, mask):
							ip_list.append(ip)
							mask_list.append(mask)
						else:
							print Fore.RED + Style.BRIGHT + "\n* The file should contain only ip network addresses(ranges), not a concrete ip addresses"
							print "\n* Please verify your file: " + Fore.YELLOW + Style.BRIGHT + file + " (line %s)" % str(count)
							sys.exit()
					else:
						print Fore.RED + Style.BRIGHT + "\n* The following line is unacceptable (line %s): \n" % str(count)
						print Fore.YELLOW + Style.BRIGHT + "'" + line + "'"
						print Fore.RED + Style.BRIGHT + "\n* Please verify your file: " + Fore.YELLOW + Style.BRIGHT + file
						sys.exit()

			#print ip_list
			#print mask_list
		except IOError as err:
			print Fore.RED + Style.BRIGHT + str(err)
			print Fore.RED + Style.BRIGHT + "\n* File " + Fore.YELLOW + Style.BRIGHT + file + Fore.RED + Style.BRIGHT + " does not exist! Please check and try again!\n"
			print Fore.WHITE + Style.BRIGHT
			sys.exit()

		#Checking octets
		for index, each_ip in enumerate(ip_list):
			a = each_ip.split(".")
			if (len(a) == 4) and (1 <= int(a[0]) <= 223) and (int(a[0]) != 127) and (int(a[0]) != 169 or int(a[1]) != 254) and (0 <= int(a[1]) <= 255 and 0 <= int(a[2]) <= 255 and 0 <= int(a[3]) <= 255):
				check = True
				continue
			else:
				print Fore.RED + Style.BRIGHT + "\n* This ip address: " + Fore.YELLOW + Style.BRIGHT + each_ip + Fore.RED + Style.BRIGHT + " is unacceptable! (line %d)" % (index + 1)
				print "\n* Please verify your file!"
				check = False
				break

		if check == True:
			print Fore.GREEN + Style.BRIGHT + "\n* All ip addresses in the file " + Fore.YELLOW + Style.BRIGHT + file + Fore.GREEN + Style.BRIGHT + " are verified and valid!\n"
			break
		elif check == False:
			sys.exit()

	return ip_list, mask_list


def ping(ip):
	"""Documentation string for ping function"""

	#Checking ip reachability
	#print Fore.BLUE + Style.BRIGHT + "* Checking IP reachability for --> " + Fore.YELLOW + Style.BRIGHT + ip

	if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
		ping_reply = subprocess.call(["ping", "-c", "2", "-w", "3", "-q", "-n", ip], stdout = subprocess.PIPE)
	elif sys.platform.startswith("win"):
		ping_reply = subprocess.call(["ping", "-n", "2", "-w", "2", ip], stdout = subprocess.PIPE)

	if ping_reply == 0:
		available_ips.append(ip)
	elif ping_reply == 2:
		pass
		#print Fore.RED + Style.BRIGHT + "\n* No response from the device --> " + Fore.YELLOW + Style.BRIGHT + ip
	else:
		pass
		#print Fore.RED + Style.BRIGHT + "\n* Ping to the following device has failed --> " + Fore.YELLOW + Style.BRIGHT + ip

def create_ping_threads(ip_list):
	"""Documentation string for create_threads function"""

	threads = []
	for ip in ip_list:
		th = threading.Thread(target = ping, args = (ip,))
		th.start()
		threads.append(th)

	for th in threads:
		th.join()


def get_net_addr(ip, dec_mask):
	"""Documentation string for get_net_addr function"""

	#Algorithm for subnet identification, based on IP and Subnet Mask

	#Convert mask to binary string

	netmask = "1" * int(dec_mask) + "0" * (32 - int(dec_mask))
	#print netmask

	no_of_zeros = netmask.count("0")
	no_of_ones = 32 - no_of_zeros
	no_of_hosts = abs(2 ** no_of_zeros - 2)

	#print "ones " + str(no_of_ones)
	#print "zeros " + str(no_of_zeros)
	#print no_of_hosts

	#Convert IP to binary string

	ip_octets_padded = []
	ip_octets_decimal = ip.split(".")

	for octet_index in range(0, len(ip_octets_decimal)):
		bin_octet = bin(int(ip_octets_decimal[octet_index])).split("b")[1]

		if len(bin_octet)<8:
			bin_octet_padded = bin_octet.zfill(8)
			ip_octets_padded.append(bin_octet_padded)
		else:
			ip_octets_padded.append(bin_octet)

	binary_ip = "".join(ip_octets_padded)
	#print binary_ip

	net_addr_bin = binary_ip[:(no_of_ones)] + "0" * no_of_zeros
	#print net_addr_bin

	broad_addr_bin = binary_ip[:(no_of_ones)] + "1" * no_of_zeros
	#print broad_addr_bin

	net_addr_bin_list = []

	for i in range(0, 32, 8):
		oc = net_addr_bin[i:i+8]
		net_addr_bin_list.append(oc)

	#print net_addr_bin_list

	net_addr_dec_list = []
	for i in net_addr_bin_list:
		oc_dec = int(i, 2)
		net_addr_dec_list.append(str(oc_dec))

	net_addr_dec = ".".join(net_addr_dec_list)
	#print net_addr_dec

	return net_addr_dec

def get_all_net_hosts(ip, dec_mask):
	"""Documentation string for get_all_net_hosts function"""

	network = ipaddress.ip_network(u"%s/%s" % (ip, dec_mask))

	net_hosts = [str(host) for host in network.hosts()]

	return net_hosts

def print_available_ips():
	"""Documentation string for get_available_ips function"""
	pprint(available_ips)

def chech_loc_ifaces():
	"""Documentation string for check_loc_ifaces function"""

	iface_list = netifaces.interfaces()
	#print iface_list

	for iface in iface_list:
	 	try:
	 		ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]
	 		#pprint(ip)
	 		if ip in available_ips:
	 			#print "\n I'll remove the following interface from the list because it's mine interface:) --> " + Fore.YELLOW + Style.BRIGHT + iface
	 			#print Fore.WHITE + Style.BRIGHT + "\n"
	 			available_ips.remove(ip)
	 	except KeyError:
	 		#print "Error with interface: " + Fore.YELLOW + Style.BRIGHT + iface
	 		#print Fore.WHITE + Style.BRIGHT + "\n"
	 		continue


def pass_is_valid(file):
	"""docustr"""

	pass_list = []

	while True:
		if os.path.isfile(file) == True:
			with open(file) as myfile:
				myfile.seek(0)

				if not myfile.read(1):
					print Fore.RED + Style.BRIGHT + "* File " + Fore.YELLOW + file + Fore.RED + Style.BRIGHT + " is empty!"
					print "* Please verify your file!"
					sys.exit()

				myfile.seek(0)
				for line in myfile:
					if line.rstrip("\n") in pass_list:
						continue
					pass_list.append(line.rstrip("\n"))
			break
		else:
			print Fore.RED + Style.BRIGHT + "\n* File " + Fore.YELLOW + Style.BRIGHT + file + Fore.RED + Style.BRIGHT + " does not exist! Please check and try again!\n"
			print Fore.WHITE + Style.BRIGHT
			sys.exit()

	print Fore.GREEN + Style.BRIGHT + "* File with passwords exists: " + Fore.YELLOW + Style.BRIGHT + file
	return pass_list

def print_version_info():
	"""Docs"""
	for host in dev_ver_info:
		print Fore.GREEN + Style.BRIGHT + "\n############################### General information for the device: %s ###############################" % host["hostname"]

		print "System type: %s" % host["sys_type"]
		print "Hardware platform: %s" % host["hard_platform"]
		print "Software name: %s" % host["soft_name"]
		print "Software version: %s" % host["soft_ver"]
		print "Image file: %s" % host["image"]
		print "Processor type: %s" % host["proc_type"]
		print "Processor frequency: %s MHz" % host["proc_freq"]
		print "Main (RAM) memory: %s Kbytes" % host["ram_mem"]
		print "Shared memory: %s Kbytes" % host["shared_mem"]
		print "NVRAM: %s Kbytes" % host["nvram"]
		print "Configuration register: %s" % host["conf_reg"]
		print "\nEoL information for the software: Cisco %s %s" % (host["hard_platform"], host["soft_ver"])
		print "\tEnd of Sales Date(EoS): %s" % host["eos"]
		print "\tLast day of Support: %s" % host["last_day_of_sup"]
		print "\tEnd of S/W Maintainence Releases Date(EoL): %s" % host["eol"]

def write_ver_info():
	"""Docs"""

	filename = r"./results/dev_general.txt"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()

	output_file = open(filename, "w")

	for host in dev_ver_info:
		print >>output_file, "############################### General information for the device: %s ###############################" % host["hostname"]

		print >>output_file, "System type: %s" % host["sys_type"]
		print >>output_file, "Hardware platform: %s" % host["hard_platform"]
		print >>output_file, "Software name: %s" % host["soft_name"]
		print >>output_file, "Software version: %s" % host["soft_ver"]
		print >>output_file, "Image file: %s" % host["image"]
		print >>output_file, "Processor type: %s" % host["proc_type"]
		print >>output_file, "Processor frequency: %s MHz" % host["proc_freq"]
		print >>output_file, "Main (RAM) memory: %s Kbytes" % host["ram_mem"]
		print >>output_file, "Shared memory: %s Kbytes" % host["shared_mem"]
		print >>output_file, "NVRAM: %s Kbytes" % host["nvram"]
		print >>output_file, "Configuration register: %s" % host["conf_reg"]
		print >>output_file, "\nEoL information for the software: Cisco %s %s" % (host["hard_platform"], host["soft_ver"])
		print >>output_file, "\tEnd of Sales Date(EoS): %s" % host["eos"]
		print >>output_file, "\tLast day of Support: %s" % host["last_day_of_sup"]
		print >>output_file, "\tEnd of S/W Maintainence Releases Date(EoL): %s\n" % host["eol"]

	output_file.close()
	print Fore.BLUE + Style.BRIGHT + "\n* General information for each device is saved to " + Fore.YELLOW + filename
	print Fore.WHITE + Style.BRIGHT + "\n"



def print_iface_info():
	"""Docs"""

	for host in dev_iface_info.keys():
		print Fore.GREEN + Style.BRIGHT + "\n############################### Interface information for the device: %s ###############################" % host

		#["iface", "phy_st", "prot_st", "description", "ip_addr", "mtu", "bandwidth"]
		for each_dict in dev_iface_info[host]:
			print "----- %s -----" % each_dict["iface"]
			if each_dict["ip_addr"] == "":
				print "\tIP address: unassigned"
			else:
				print "\tIP address: %s" % each_dict["ip_addr"]
			print "\tOperational state: %s" % each_dict["phy_st"]
			print "\tProtocol state: %s" % each_dict["prot_st"]
			print "\tDescription: %s" % each_dict["description"]
			print "\tMTU: %s bytes" % each_dict["mtu"]
			print "\tBandwidth: %s Kbit/sec" % each_dict["bandwidth"]

def write_iface_info():
	"""Docs"""

	filename = r"./results/dev_interfaces.txt"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()


	output_file = open(filename, "w")

	for host in dev_iface_info.keys():
		print >>output_file, "\n############################### Interface information for the device: %s ###############################" % host

		#["iface", "phy_st", "prot_st", "description", "ip_addr", "mtu", "bandwidth"]
		for each_dict in dev_iface_info[host]:
			print >>output_file, "----- %s -----" % each_dict["iface"]
			if each_dict["ip_addr"] == "":
				print >>output_file, "\tIP address: unassigned"
			else:
				print >>output_file, "\tIP address: %s" % each_dict["ip_addr"]
			print >>output_file, "\tOperational state: %s" % each_dict["phy_st"]
			print >>output_file, "\tProtocol state: %s" % each_dict["prot_st"]
			print >>output_file, "\tDescription: %s" % each_dict["description"]
			print >>output_file, "\tMTU: %s bytes" % each_dict["mtu"]
			print >>output_file, "\tBandwidth: %s Kbit/sec" % each_dict["bandwidth"]

	output_file.close()
	print Fore.BLUE + Style.BRIGHT + "\n* Interface information for each device is saved to " + Fore.YELLOW + filename
	print Fore.WHITE + Style.BRIGHT + "\n"


def print_module_info():
	"""Documentation string for print_module_info() function"""

	for host in dev_module_info.keys():
		print Fore.GREEN + Style.BRIGHT + "\n############################### Module information for the device: %s ###############################" % host
		print "\n********************  ADAPTERS  ********************"

		for each_dict in dev_module_info[host][0]:
			print "----- Slot %s -----" % each_dict["slot_no"]
			print "\tModule: %s" % each_dict["module_name"]
			print "\tStatus: %s" % each_dict["status"]
			print "\tPort number: %s" % each_dict["port_no"]
			print "\tPort adapter insertion time: %s ago" % each_dict["insert_time"]
			print "\tSerial number: %s" % each_dict["serial_no"]
			print "\tHardware revision: %s" % each_dict["hard_rev"]
			print "\tPID: %s" % each_dict["pid"]

		print "\n******************** WICS ********************"
		for each_dict in dev_module_info[host][1]:
			print "----- Slot %s -----" % each_dict["slot_no"]
			print "\tModule: Serial %s" % each_dict["module_name"]
			print "\tStatus: analyzed"
			print "\tSerial number: %s" % each_dict["serial_no"]
			print "\tHardware revision: %s" % each_dict["hard_rev"]
			print "\tPID: %s" % each_dict["pid"]

def write_module_info():
	"""Documentation string for write_module_info() function"""

	filename = r"./results/dev_modules.txt"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()

	output_file = open(filename, "w")

	for host in dev_module_info.keys():
		print >>output_file, "\n############################### Module information for the device: %s ###############################\n" % host

		print >>output_file, "******************** ADAPTERS ********************\n"
		for each_dict in dev_module_info[host][0]:
			print >>output_file, "----- Slot %s -----\n" % each_dict["slot_no"]
			print >>output_file, "\tModule: %s\n" % each_dict["module_name"]
			print >>output_file, "\tStatus: %s\n" % each_dict["status"]
			print >>output_file, "\tPort number: %s\n" % each_dict["port_no"]
			print >>output_file, "\tPort adapter insertion time: %s ago\n" % each_dict["insert_time"]
			print >>output_file, "\tSerial number: %s\n" % each_dict["serial_no"]
			print >>output_file, "\tHardware revision: %s\n" % each_dict["hard_rev"]
			print >>output_file, "\tPID: %s\n" % each_dict["pid"]

		print >>output_file, "\n******************** WICS ********************\n"
		for each_dict in dev_module_info[host][1]:
			print >>output_file, "----- Slot %s -----\n" % each_dict["slot_no"]
			print >>output_file, "\tModule: Serial %s\n" % each_dict["module_name"]
			print >>output_file, "\tStatus: analyzed\n"
			print >>output_file, "\tSerial number: %s\n" % each_dict["serial_no"]
			print >>output_file, "\tHardware revision: %s\n" % each_dict["hard_rev"]
			print >>output_file, "\tPID: %s\n" % each_dict["pid"]

	output_file.close()
	print Fore.BLUE + Style.BRIGHT + "\n* Module information for each device is saved to " + Fore.YELLOW + filename
	print Fore.WHITE + Style.BRIGHT + "\n"

def write_cred_csv():
	"""Docs"""

	filename = r"./results/dev_credentials.csv"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()


	output_file = open(filename, "w")

	print >>output_file, "Device,Username,Password,Management IP"

	for each_dict in dev_manage_info:
		print >>output_file, "%s,%s,%s,%s" % (each_dict["hostname"], each_dict["username"], each_dict["password"], each_dict["manage_ip"])

	output_file.close()

	print Fore.BLUE + Style.BRIGHT + "* Credentials for each device is saved to " + Fore.YELLOW + filename + Fore.BLUE + Style.BRIGHT + " file!"
	print "* You can open it using Microsoft Excel"
	print Fore.WHITE + Style.BRIGHT + "\n"

def draw_topology():
	"""Documentation string for draw_topology() function"""

	print Fore.CYAN + Style.BRIGHT + "\n* Generating network topology...\n" + Fore.BLUE + Style.BRIGHT

	#Drawing the topology using the list of neighborships
	G = nx.Graph()
	G.add_edges_from(neighborship_dict.keys())
	pos = nx.spring_layout(G, k = float(len(dev_manage_info)), iterations = 70)
	nx.draw_networkx_labels(G, pos, font_size = 9, font_family = "sans-serif", font_weight = "bold")
	nx.draw_networkx_edges(G, pos, width = 4, alpha = 0.4, edge_color = 'black')
	nx.draw_networkx_edge_labels(G, pos, neighborship_dict, label_pos = 0.3, font_size = 6)
	nx.draw(G, pos, node_size = 700, with_labels = True)
	matp.show()
