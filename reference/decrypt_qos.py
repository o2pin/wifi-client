#!/usr/bin/python3
# -*- coding: utf-8 -*-​
import sys, os, time, re, argparse, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import Dot11, RadioTap, Dot11CCMP, Dot11FCS
from Crypto.Cipher import AES
from subprocess import run, PIPE



def decrypt(packet, tk):

    addr2 = re.sub(":","",packet.addr2)
    print("addr2 : ", addr2)
    # addr4 = re.sub(":","",fcs.addr4)
    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(packet.PN5,packet.PN4,packet.PN3,packet.PN2,packet.PN1,packet.PN0)
    print("PN : ",PN)
    # Priority Octet "00" 
    nonce = bytes.fromhex("00") + bytes.fromhex(addr2) + bytes.fromhex(PN)               
    TK = bytes.fromhex(tk) #TK
    print("密文 : ", packet.data.hex())
    # cipher_text = packet.data[:-8]
    cipher_text = packet.data
    # print("cipher_text : ", cipher_text.hex())
    
    # 真正解密过程
    cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
    cipher2 = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
    # cipher.update(AAD)
    plain_text = cipher.decrypt(cipher_text)
    
    p2 = LLC(plain_text)
    p2.show()
    print("明文 : ", plain_text.hex())            # 解密后明文
    
    
    # mingwen = "aaaa0300000008004500015ac10500008011788e00000000ffffffff0044004301462d5c01010600ccbfab040000000000000000000000000000000000000000e4029b5cfefe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033d0701e4029b5cfefe3204c0a804770c0d62696368656e7368616f2d7063511000000062696368656e7368616f2d70633c084d53465420352e30370e0103060f1f212b2c2e2f7779f9fcffe818890fb7a5a580"
    # mac_client = "001d4320192d"
    # msg = mingwen.replace("e4029b5cfefe", mac_client)
    # miwen = cipher2.encrypt(bytes.fromhex(plain_text.hex()))
    # print("再加密密文 : ", miwen.hex())
    # return miwen.hex()



p = "000012002e48000010026c09a000e805000088413a015af927bf6c9ee4029b5cfefeffffffffffff10000000030000200000000073bada60300cc235260bc5daddbcaec05c26efded06b11ca42ac02d05e1892ca308b47ed7a35ab82eaf87faf17198ae2"

packet = RadioTap(bytes.fromhex(p))[Dot11]

tk = "597bd7b680f4efecb94c31ab64a9f249"
e = decrypt(packet, tk)
