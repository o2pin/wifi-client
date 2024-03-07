import logging
import scapy
import subprocess
import sys
import re
import time
from scapy.arch import str2mac, get_if_raw_hwaddr
# import pysnooper

# FORMAT = "%(asctime)s::  [%(filename)s:%(lineno)d] --- %(message)s"
# logging.basicConfig(level = logging.DEBUG)


def get_iface_type(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("type (\w+)")
	return str(p.search(output).group(1))

def get_monitor_channel(iface):
    output = str(subprocess.check_output(["iwlist", iface, "channel"]))
    current_freq_pattern = r"Current Frequency.*\(Channel (\d+)\)"
    match = re.search(current_freq_pattern, output)
    
    channel_number = None
    if match:
        channel_number = match.group(1)
        # print(channel_number)
    
    return channel_number

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

def set_monitor_channel(nic_mon, channel=1):
    subprocess.check_output(["ifconfig", nic_mon, "down"])
    subprocess.check_output(["ifconfig", nic_mon, "up"])
    subprocess.check_output(["iw", "dev" , nic_mon, "set", "channel", str(channel)])
    
    
def set_monitor_mode(iface, channel=1, up=True, mtu=1500):
    # Note: we let the user put the device in monitor mode, such that they can control  optional
    #       parameters such as "iw wlan0 set monitor active" for devices that support it.
    if get_iface_type(iface) != "monitor":
        # Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor      interface. The following ugly
        # sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
        subprocess.check_output(["ifconfig", iface, "down"])
        subprocess.check_output(["iw", iface, "set", "type", "monitor"])
        time.sleep(0.5)
        subprocess.check_output(["iw", iface, "set", "type", "monitor"])
    
    # set_monitor_channel(iface, channel)

    if up:
        subprocess.check_output(["ifconfig", iface, "up"])
        subprocess.check_output(["ifconfig", iface, "mtu", str(mtu)])
 


# @pysnooper.snoop()
def ensure_interface_mode(iface, channel=1):    
    # 0. Enable Wi-Fi
    subprocess.check_output(["rfkill", "unblock", "wifi"])
    nic_mon = "mon" + iface[:12]    # drop last 2 bytes mac address 
    # 1. Check if the interfaces exists
    try:
        scapy.arch.get_if_index(iface)
    except OSError:
        logging.info(f"Error : Interface {iface} doesn't appear to exist.")
        quit(1)

    # 2. Create second virtual interface in monitor mode. Note: some kernels
    #    don't support interface names of 15+ characters.

    # Only create a new monitor interface if it does not yet exist
    try:
        scapy.arch.get_if_index(nic_mon)
        # return nic_mon
    except OSError:
        subprocess.call(["iw", nic_mon, "del"], 
                        stdout=subprocess.PIPE, 
                        stdin=subprocess.PIPE)
        subprocess.check_output(["ifconfig", iface, "down"])
        subprocess.check_output(["iw", iface, "interface", "add", nic_mon, "type", "monitor"])
        subprocess.check_output(["ifconfig", iface, "up"])
        
    # get_monitor_channel()
    
    # 3. Enable monitor mode. This is similar to what airmon-ng does.
    set_monitor_mode(nic_mon, channel)
    logging.info(f"Using interface {nic_mon} ({get_device_driver(nic_mon)}) to inject frames.")
    
    return nic_mon