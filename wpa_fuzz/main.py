import argparse
import logging
logging.basicConfig(level=logging.DEBUG)
from connect import *
from pprint import pprint

# Metadata.
NAME = "Wi-Fi Fuzz"
VERSION = "1.0"
 
def main():      
    # Arguments.
    parser = argparse.ArgumentParser(description=f"{NAME} (Version {VERSION}).")
    parser.add_argument('iface', help="Interface.")
    parser.add_argument('--ssid', type=str, default=None, help="Name of test to run.")
    parser.add_argument('--psk', type=str, default=None, help="Config wifi psk.")
    parser.add_argument('--ap-mac', type=str, default=None, help="Config ap mac.")
    parser.add_argument('--client-mac', type=str, default=None, help="Config ap mac.")
    parser.add_argument('--channel', type=str, default=None, help="Wlan Channel.")
    parser.add_argument('--debug', type=int, default=0, help="Debug output level.")
    opt = parser.parse_args()
    logging.info(opt)
    logging.info('start main')  # will not print anything

    config = WiFi_Object(
        iface = opt.iface,
        ssid = opt.ssid if opt.ssid else "shuimuyulin", 
        psk = opt.psk if opt.psk else "smyl2020x7s3",       
        mac_ap = opt.ap_mac if opt.ap_mac else "58:41:20:FD:26:ED",           # xiaomi  hotpoint
        mac_client = opt.client_mac if opt.client_mac else "00:1d:43:20:18:d4",        # 00:1d:43:20:19:2d , mt7921au 第一块
        anonce = "", 
        snonce = "", 
        payload = ("")
    )
    pprint(vars(config))
    #   addr0     =   (RA=DA)  目的地址
    #   addr1     =   (TA=SA)  中间人
    #   addr2     =   (BSSID/STA)   AP/Client  源地址
    
    conf.iface = config.iface
    mon_ifc = Monitor(config.iface, config.mac_client.lower(), config.mac_ap.lower())
    # print(config.__dict__)
    connectionphase_0 = ConnectionPhase(mon_ifc, config.mac_client, config.mac_ap)
    
    # 链路认证
    print("\n-------------------------\nLink Authentication Request : ")
    connectionphase_0.send_authentication()
    
    print("\n-------------------------\nLink Authentication Response : ")
    if connectionphase_0.state == "Authenticated":
        print("STA is authenticated to the AP!")
    else:
        print("STA is NOT authenticated to the AP!")
        return 0
    time.sleep(0)
    # 链路关联
    print("\n-------------------------\nLink Assocation Request : ")
    connectionphase_0.send_assoc_request(ssid=config.ssid)
    
    print("\n-------------------------\nLink Assocation Response : ")
    if connectionphase_0.state == "Associated":
        print("STA is connected to the AP!")
    else:
        print("STA is NOT connected to the AP!")
        return 0
    
    # 密钥协商
    connectionphase_1 = eapol_handshake(config)
    connectionphase_1.run()
    
    
if __name__ == "__main__":
    sys.exit(main())
    