import logging
import scapy
import subprocess
import re
import time

def ensure_interface_mode(iface):
    # 如果传入的iface是monitor模式，则直接使用，否则创建一个虚拟接口，配置为monitor模式
    if get_iface_type(iface) == "monitor":
        logging.info("Iface:%s is aready monitor mode", iface)
        return iface

    # Only create a new monitor interface if it does not yet exist
    nic_mon = "mon" + iface[:6]
    try:
        scapy.arch.get_if_index(nic_mon)
    except IOError:
        subprocess.call(["iw", nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        subprocess.check_output(["iw", iface, "interface", "add", nic_mon, "type", "monitor"])

    # 3. Enable monitor mode. This is similar to what airmon-ng does.
    logging.info("Create iface:{} monitor mode", iface)
    set_monitor_mode(nic_mon)
    return nic_mon

def get_iface_type(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("type (\w+)")
	return str(p.search(output).group(1))

def get_iface_mac(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("addr ([\w:]+)")
	return str(p.search(output).group(1))

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