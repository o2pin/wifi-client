import argparse
import logging
from src.connect import *
from pprint import pprint
from utils.interface_mode import *

FORMAT = '%(asctime)s::%(filename)s:%(funcName)s:%(lineno)d ---- %(message)s'
logging.basicConfig(level = logging.DEBUG, format=FORMAT)

# Metadata.
NAME = "Wi-Fi Fuzz"
VERSION = "1.0"
 
def main():      
    # Arguments.
    parser = argparse.ArgumentParser(description=f"{NAME} (Version {VERSION}).")
    parser.add_argument('--iface', type=str, required=True, help="Interface name.")
    parser.add_argument('--mac-client', type=str, default=None, help="Interface mac.")
    parser.add_argument('--ssid', type=str, required=True, help="SSID.")
    parser.add_argument('--mac-ap', type=str, required=True, help="AP mac.")
    parser.add_argument('--psk', type=str, required=True, help="WIFI psk.")
    parser.add_argument('--fuzz_scene', type=int, default=0, help="场景id.")
    opt = parser.parse_args()
    logging.info(opt)
    logging.info('start main')  # will not print anything

    iface = ensure_interface_mode(opt.iface)
    mac_client = opt.mac_client if opt.mac_client else get_iface_mac(iface)
    config = WiFi_Object(
        iface = iface,
        ssid = opt.ssid, 
        psk = opt.psk,       
        mac_ap = opt.mac_ap,
        mac_client = mac_client,
        anonce = "", 
        snonce = "", 
        payload = ("")
    )
    pprint(vars(config))
    
    rsn = RSN()
    rsn_info = rsn.get_rsn_info()       # rsn info
    conf.iface = config.iface
    monitor = Monitor(config.iface, config.mac_client.lower(), config.mac_ap.lower())
    connectionphase_1 = ConnectionPhase(monitor, config.mac_client, config.mac_ap)
    
    # 链路认证
    logging.info("\n-------------------------Link Authentication Request : ")
    connectionphase_1.send_authentication()
    
    if connectionphase_1.state == "Authenticated":
        logging.info("STA is authenticated to the AP!")
    else:
        logging.info("STA is NOT authenticated to the AP!")
        sys.exit(1)
    # 场景0 测试认证过程
    if opt.fuzz_scene == 0:
        sys.exit(0)

    # 链路关联
    logging.info("\n-------------------------Link Assocation Request : ")
    connectionphase_1.send_assoc_request(ssid=config.ssid, rsn_info=rsn_info)
    
    if connectionphase_1.state == "Associated":
        logging.info("STA is connected to the AP!")
    else:
        logging.info("STA is NOT connected to the AP!")
        sys.exit(1)
    # 场景1 测试关联过程
    if opt.fuzz_scene == 1:
        sys.exit(0)
    
    # 密钥协商
    connectionphase_2 = eapol_handshake(DUT_Object=config, rsn_info=rsn_info)
    TK = connectionphase_2.run()
    
    if len(TK) > 1:
        logging.info("WiFi 握手完成!")
    else:
        sys.exit(1)
    # 场景2 测试密钥协商
    if opt.fuzz_scene == 2:
        sys.exit(0)
    
    # 和 AP 加密通信
    logging.info("\n-------------------------Send Request : ")
    logging.info(" TK : ".format(TK))
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
    logging.info("密文 : {}".format(Ciphertext))
    
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