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
    parser.add_argument('--iface', type=str, default="wlan1", help="Interface.")
    parser.add_argument('--client-mac', type=str, default="00:1d:43:20:18:d4", help="Config ap mac.")
    parser.add_argument('--ssid', type=str, default="shuimuyulin", help="Name of test to run.")
    parser.add_argument('--ap-mac', type=str, default="58:41:20:FD:26:ED", help="Config ap mac.")
    parser.add_argument('--psk', type=str, default="smyl2021x7s3", help="Config wifi psk.")
    parser.add_argument('--channel', type=str, default=None, help="Wlan Channel.")
    parser.add_argument('--debug', type=int, default=0, help="Debug output level.")
    opt = parser.parse_args()
    logging.info(opt)
    logging.info('start main')  # will not print anything

    config = WiFi_Object(
        iface = opt.iface,
        ssid = opt.ssid, 
        psk = opt.psk,       
        mac_ap = opt.ap_mac,
        mac_client = opt.client_mac,
        anonce = "", 
        snonce = "", 
        payload = ("")
    )
    pprint(vars(config))
    # smyl = WiFi_Object(
    #     iface = "wlan0mon",
    #     ssid = "shuimuyulin", 
    #     psk = "smyl2021x7s3",       
    #     mac_ap = "58:41:20:FD:26:ED",           # smyl
    #     mac_client = "00:1d:43:20:18:d4",        # 00:1d:43:20:19:2d , mt7921au 第一块
    #     anonce = "", 
    #     snonce = "", 
    #     payload = ("")
    #     )
    # smylguest = WiFi_Object(
    #     iface = "wlan0mon",
    #     ssid = "shuimuyulin-guest", 
    #     psk = "smyl2021",       
    #     mac_ap = "5a:41:20:1d:26:ed",           #
    #     mac_client = "00:1d:43:20:19:2d",        # 00:1d:43:20:19:2d , mt7921au 第一块
    #     anonce = "", 
    #     snonce = "", 
    #     payload = ("")
    #     )
    # xiaom_hotspot = WiFi_Object(
    #     iface = "wlan0mon",
    #     ssid = "testwifi", 
    #     psk = "99999999",       
    #     mac_ap = "F6:71:82:F6:32:19",           # xiaomi hotspot
    #     mac_client = "00:1d:43:20:19:2d",        # mt7921au 第一块
    #     # mac_client = "00:a1:b0:79:03:f6",        # rt3070 第一块
    #     anonce = "", 
    #     snonce = "", 
    #     payload = ("")
    #     )
    
    rsn = RSN()
    rsn_info = rsn.get_rsn_info()       # rsn info
    conf.iface = config.iface
    monitor = Monitor(config.iface, config.mac_client.lower(), config.mac_ap.lower())
    connectionphase_1 = ConnectionPhase(monitor, config.mac_client, config.mac_ap)
    
    # 链路认证
    print("\n-------------------------\nLink Authentication Request : ")
    connectionphase_1.send_authentication()
    
    if connectionphase_1.state == "Authenticated":
        print("STA is authenticated to the AP!")
    else:
        print("STA is NOT authenticated to the AP!")
        sys.exit(1)
    time.sleep(1)
    # 链路关联
    print("\n-------------------------\nLink Assocation Request : ")
    connectionphase_1.send_assoc_request(ssid=config.ssid, rsn_info=rsn_info)
    
    if connectionphase_1.state == "Associated":
        print("STA is connected to the AP!")
    else:
        print("STA is NOT connected to the AP!")
        sys.exit(1)
    
    # 密钥协商
    connectionphase_2 = eapol_handshake(DUT_Object=config, rsn_info=rsn_info)
    TK = connectionphase_2.run()
    
    if len(TK) > 1:
        print("WiFi 握手完成!")
    else:
        sys.exit(1)
    
    # 和 AP 加密通信
    print("\n-------------------------\nSend Request : ")
    print(" TK : ", TK)
    # TK = ptk[32:48]
    PN = "000000000001"      # = Dot11CCMP(ext_iv=1, PN0=1) = Dot11CCMP(bytes.fromhex("0100002000000000"))
    qos = bytes.fromhex("00")       # 0 = tk , 1 = gtk
    nonce = qos + bytes.fromhex(config.mac_client.replace(":", "")) + bytes.fromhex(PN)
    
    generate_payload = Generate_Plain_text()
    Plain_text : packet = generate_payload.Plain_text("arp")        # arp or dhcp
    Plain_text.show()
    Plain_text = bytes(Plain_text)
    
    cipher = AES.new(bytes.fromhex(TK), AES.MODE_CCM, nonce, mac_len = 8)
    Ciphertext = cipher.encrypt(Plain_text)
    print("密文 : ", Ciphertext)
    
    
    dhcp_req = Dot11(
            type=2, 
            subtype=8,   
            FCfield=65,
            addr1=config.mac_ap,
            addr2=config.mac_client, 
            addr3=config.ff_mac, 
            SC=64)  / Dot11QoS() / Dot11CCMP(ext_iv=1, PN0=1) / Ciphertext
    dhcp_req.display()
    send(dhcp_req, iface = config.iface)
    
if __name__ == "__main__":
    sys.exit(main())