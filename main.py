import argparse
import logging
from pprint import pprint
from src import connect_wpa3 as wpa3
from src import connect as wpa2
from utils.interface_mode import ensure_interface_mode,get_iface_mac
import sys

FORMAT = '%(asctime)s::%(filename)s:%(funcName)s:%(lineno)d ---- %(message)s'
logging.basicConfig(level = logging.DEBUG, format=FORMAT)

# Metadata.
NAME = "Wi-Fi Fuzz"
VERSION = "1.0"

def main():
    # Arguments.
    parser = argparse.ArgumentParser(description=f"{NAME} (Version {VERSION}).")
    parser.add_argument('--iface', type=str, required=True, help="Interface name.")
    parser.add_argument('--sta-mac', type=str, default=None, help="Interface mac.")
    parser.add_argument('--ssid', type=str, required=True, help="SSID.")
    parser.add_argument('--ap-mac', type=str, required=True, help="AP mac.")
    parser.add_argument('--psk', type=str, required=True, help="WIFI psk.")
    parser.add_argument('--scene', type=int, default=0, help="场景id.")
    parser.add_argument('--suite', type=str, default="WPA2", help="测试套件.")  # WPA2 WPA3
    opt = parser.parse_args()
    logging.info(opt)
    logging.info('start main')  # will not print anything
    iface = ensure_interface_mode(opt.iface)
    sta_mac = opt.sta_mac if opt.sta_mac else get_iface_mac(iface)

    if opt.suite == "WPA3":
        logging.info("WPA3 test suite")
        wpa3.test(
            iface=iface,
            ssid = opt.ssid,
            psk = opt.psk,
            ap_mac = opt.ap_mac,
            sta_mac = sta_mac,
            scene = opt.scene
       )
    elif opt.suite == "WPA2":
        logging.info("WPA2 test suite")
        wpa2.test(
            iface=iface,
            ssid = opt.ssid,
            psk = opt.psk,
            ap_mac = opt.ap_mac,
            sta_mac = sta_mac,
            scene = opt.scene
        )
    else:
        logging.error("Not support suite {}", opt.suite)
        sys.exit(1)

if __name__ == "__main__":
    main()
