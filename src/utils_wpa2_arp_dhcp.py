#!/usr/bin/python3
# -*- coding: utf-8 -*-​
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Raw
from scapy.layers.dot11 import (
    RadioTap, 
    LLC, 
    Dot11, 
    sendp,
    Dot11CCMP,
    Dot11QoS
    )
from scapy.layers.l2 import SNAP
from Crypto.Cipher import AES
from .utils_wpa1_wpa2_crypt import CCMPCrypto,Gen_Target_layer


FORMAT = '%(asctime)s::%(filename)s:%(funcName)s:%(lineno)d ---- %(message)s'
logging.basicConfig(level = logging.DEBUG, format=FORMAT)


class ONCE_REQ:
    @staticmethod
    def request_once(config = None, req_type = 'DHCP' , router_ip = '192.168.0.1'):
        # dot11 layer
        dot11_packet = Dot11(
            type=2,
            subtype=8,
            FCfield=65,
            addr1=config.mac_ap,
            addr2=config.mac_sta,
            addr3=config.ff_mac,
            SC=64)  / Dot11QoS() / Dot11CCMP(ext_iv=1, PN0=1)

        # 明文
        Plain_text : packet = Gen_Target_layer.gen(type = req_type, mac_self= bytes.fromhex((config.mac_sta).replace(':','')), router_ip = router_ip)        # arp or dhcp
        # Plain_text.show()
        Plain_text = LLC() / SNAP() / Plain_text
        Plain_text = bytes(Plain_text)
        
        # 密文
        packet = dot11_packet
        PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(packet.PN5,packet.PN4,packet.PN3,packet.PN2,packet.PN1,packet.PN0)
        priority = "00"       # 00 = tk , 01 = gtk
        Nonce = CCMPCrypto.ccmp_get_nonce(priority=priority , addr=config.mac_sta, pn=PN)
        cipher = AES.new(bytes.fromhex(config.TK), AES.MODE_CCM, Nonce, mac_len = 8)
        Ciphertext = cipher.encrypt(Plain_text)
        logging.info(f"密文 : {Ciphertext.hex()}")
        
        # 密文校验值 mic
        AAD = CCMPCrypto.ccmp_get_aad(p=dot11_packet)
        MIC = CCMPCrypto.cbc_mac(key = bytes.fromhex(config.TK), plaintext=Plain_text,aad=AAD,nonce=Nonce)    # 密文mic

        # 返回密文
        return dot11_packet / Ciphertext / Raw(MIC)
        
        

class CONFIG:
    pass


if __name__ == '__main__':
    config = CONFIG()

    setattr(config, 'iface', 'monwlan0')
    setattr(config, 'mac_ap', '02:00:00:00:00:00')
    setattr(config, 'mac_sta','02:00:00:00:01:00')
    setattr(config, 'ff_mac', 'ff:ff:ff:ff:ff:ff')
    setattr(config, 'TK', '00000000000000000000000000000000')
    # ARP or DHCP
    # we_will_send = 'DHCP' 
    we_will_send = 'ARP' 


    packet = ONCE_REQ.request_once(  config= config , req_type= we_will_send)
    sendp(RadioTap() / packet, 
        iface = config.iface, 
        verbose=0
        )
    logging.info(f'We sent 1 {we_will_send} ! ')