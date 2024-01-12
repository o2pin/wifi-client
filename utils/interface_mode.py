import logging
import scapy
import subprocess
import sys
import re
import time
from scapy.arch import str2mac, get_if_raw_hwaddr

FORMAT = "%(asctime)s::  [%(filename)s:%(lineno)d] --- %(message)s"
logging.basicConfig(level = logging.DEBUG, format=FORMAT)


def get_iface_type(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("type (\w+)")
	return str(p.search(output).group(1))


def get_iface_mac(iface):
	return str2mac(get_if_raw_hwaddr(iface)[1])


#### Linux ####

def get_device_driver(iface):
	path = "/sys/class/net/%s/device/driver" % iface
	try:
		output = subprocess.check_output(["readlink", "-f", path])
		return output.decode('utf-8').strip().split("/")[-1]
	except:
		return None


def set_monitor_mode(iface, up=True, mtu=1500):
	# Note: we let the user put the device in monitor mode, such that they can control optional
	#       parameters such as "iw wlan0 set monitor active" for devices that support it.
	if get_iface_type(iface) != "monitor":
		# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
		# sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
		subprocess.check_output(["ifconfig", iface, "down"])
		subprocess.check_output(["iw", iface, "set", "type", "monitor"])
		time.sleep(0.5)
		subprocess.check_output(["iw", iface, "set", "type", "monitor"])

	if up:
		subprocess.check_output(["ifconfig", iface, "up"])
	subprocess.check_output(["ifconfig", iface, "mtu", str(mtu)])
 


def ensure_interface_mode(iface):    
    # 0. Enable Wi-Fi
    subprocess.check_output(["rfkill", "unblock", "wifi"])
    nic_mon = "mon" + iface[:12]
    # 1. Check if the interfaces exists
    try:
        scapy.arch.get_if_index(iface)
    except IOError:
        logging.info(f"Error : Interface {iface} doesn't appear to exist.")
        quit(1)

    # 2. Create second virtual interface in monitor mode. Note: some kernels
    #    don't support interface names of 15+ characters.

    # Only create a new monitor interface if it does not yet exist
    try:
        scapy.arch.get_if_index(nic_mon)
        # return nic_mon
    except IOError:
        subprocess.call(["iw", nic_mon, "del"], 
                        stdout=subprocess.PIPE, 
                        stdin=subprocess.PIPE)
        subprocess.check_output(["iw", iface, "interface", "add", nic_mon, "type", "monitor"])

    # 3. Enable monitor mode. This is similar to what airmon-ng does.
    set_monitor_mode(nic_mon)
    logging.info(f"Using interface {nic_mon} ({get_device_driver(nic_mon)}) to inject frames.")
    
    return nic_mon
    
    
# ensure_interface_mode(sys.argv[1])
