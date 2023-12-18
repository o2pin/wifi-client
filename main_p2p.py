import argparse
import logging
from pprint import pprint
from src import p2p

from utils.interface_mode import ensure_interface_mode,get_iface_mac

FORMAT = '%(asctime)s::%(filename)s:%(funcName)s:%(lineno)d ---- %(message)s'
logging.basicConfig(level = logging.DEBUG, format=FORMAT)

# Metadata.
NAME = "Wi-Fi Fuzz"
VERSION = "1.0"

def main():
    # Arguments.
    parser = argparse.ArgumentParser(description=f"{NAME} (Version {VERSION}).")
    parser.add_argument('--iface', type=str, required=True, help="Interface name.")
    parser.add_argument('--ap-mac', type=str, required=True, help="AP mac.")
    parser.add_argument('--scene', type=int, default=0, help="场景id.")
    parser.add_argument('--suite', type=str, default="WPA2", help="测试套件.")  # WPA2 WPA3 P2P
    parser.add_argument('--timeout', type=int, default=100, help="超时时间.")  #ms
    parser.add_argument('--listen-channel', type=int, default=11, help="监听频段.")  #1，6，11
    parser.add_argument('--seed', type=int, default=1, help="随机种子.")

    opt = parser.parse_args()
    logging.info(opt)
    logging.info('start p2p main')  # will not print anything
    iface = ensure_interface_mode(opt.iface)
    client_mac = opt.client_mac if opt.client_mac else get_iface_mac(iface)

    if opt.suite == "P2P":
        logging.info("P2P test suite")
        p2p.test(
            iface=iface,
            dst=opt.ap_mac.lower(), #字母必须为小写
            scene = opt.scene,
            timeout = opt.timeout / 1000,
            listen_channel = opt.listen_channel,
            seed=opt.seed
            )

if __name__ == "__main__":
    main()
