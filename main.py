import argparse
import logging
import sys


from utils.interface_mode import ensure_interface_mode,get_iface_mac
from src import \
    connect_wpa3 as wpa3, \
    connect_wpa1_wpa2 as wpa1_wpa2


# FORMAT = "%(asctime)s.%(msecs)d %(levelname)-8s [%(processName)s] [%(threadName)s] %(filename)s:%(lineno)d --- %(message)s"
FORMAT = "[%(pathname)s:%(lineno)d] --- %(message)s"
logging.basicConfig(level = logging.ERROR, format=FORMAT)

# ----------------------- graceful_exit ---------------------------------
import signal
from functools import wraps

graceful_exit_on_ctrl_c = lambda func: wraps(func)(lambda *a, **kw: [signal.signal(signal.SIGINT, lambda s, f: print(f"\nReceived Ctrl+C. Cleaning up and exiting...") or sys.exit(0)), func(*a, **kw)][1])


# Metadata.
NAME = "Wi-Fi Fuzz"
VERSION = "1.0"

@graceful_exit_on_ctrl_c
def main():
    # Arguments.
    parser = argparse.ArgumentParser(description=f"{NAME} (Version {VERSION}).")
    parser.add_argument('--iface', type=str, required=True, help="Interface name.")
    parser.add_argument('--channel', type=str, default='1', help="Wi-Fi channel.")
    parser.add_argument('--ssid', type=str, required=True, help="SSID.")
    parser.add_argument('--psk', type=str, required=True, help="WIFI psk.")
    parser.add_argument('--sta-mac', type=str, default=None, help="Interface mac.")
    parser.add_argument('--ap-mac', type=str, required=True, help="AP mac.")
    parser.add_argument('--timeout', type=int, default=3000, help="超时时间, ms.")
    parser.add_argument('--suite', type=str, default="WPA2", help="测试套件.") 
    parser.add_argument('--scene', type=int, default=0, help="场景id.")
    opt = parser.parse_args()
    # logging.info(opt)
    logging.info('start main')
    
    
    # iface = ensure_interface_mode(opt.iface, channel=opt.channel)
    iface = opt.iface
    sta_mac = opt.sta_mac if opt.sta_mac else get_iface_mac(opt.iface)
    timeout = opt.timeout / 1000

    if opt.suite == "WPA3":
        logging.info("WPA3 test suite")
        wpa3.test(
            iface=iface,
            ssid = opt.ssid,
            psk = opt.psk,
            ap_mac = opt.ap_mac,
            sta_mac = sta_mac,
            scene = opt.scene,
            timeout = timeout
       )
    elif opt.suite == "WPA2":
        logging.info("WPA2 test suite")
        wpa1_wpa2.test(
            iface=iface,
            ssid = opt.ssid,
            psk = opt.psk,
            ap_mac = opt.ap_mac,
            sta_mac = sta_mac,
            scene = opt.scene,
            wpa_keyver=opt.suite,
            router_ip = '192.168.4.1',
            timeout = timeout
        )
    elif opt.suite == "WPA1":
        logging.info("WPA1 test suite")
        wpa1_wpa2.test(
            iface=iface,
            ssid = opt.ssid,
            psk = opt.psk,
            ap_mac = opt.ap_mac,
            sta_mac = sta_mac,
            scene = opt.scene,
            wpa_keyver=opt.suite,
            router_ip = '192.168.4.1',
            timeout = timeout
        )
    else:
        logging.error("Not support suite {}", opt.suite)
        sys.exit(1)

if __name__ == "__main__":
    main()
