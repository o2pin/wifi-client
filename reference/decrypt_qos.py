#!/usr/bin/python3
# -*- coding: utf-8 -*-​
import sys, os, time, re, argparse, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import Dot11, RadioTap, Dot11CCMP, Dot11FCS
from Crypto.Cipher import AES
from subprocess import run, PIPE
from scapy.all import *
import binascii
import hashlib, hmac
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap


class Calc_MIC():
    
    def min_max(self, a, b):
        if len(a) != len(b): raise 'Unequal byte string lengths' 
        for entry in list(zip( list(bytes(a)), list(bytes(b)) )):
            if entry[0] < entry[1]: return (a, b)
            elif entry[1] < entry[0]: return (b, a)
        return (a, b)
    
    def calculate_WPA_PMK(self, psk, ssid):
        pmk = hashlib.pbkdf2_hmac('sha1', psk.encode(), ssid.encode(), 4096, 32)
        print("PMK : " + pmk.hex())
        
        return pmk

    def calc_ptk(self, pmk, anonce, snonce, mac_ap, mac_client):
        # print("minx_max type : ",type(mac_ap))
        macs = self.min_max(mac_ap, mac_client)
        nonces = self.min_max(anonce, snonce)
        ptk_inputs = b''.join([b'Pairwise key expansion\x00', macs[0], macs[1], nonces[0], nonces[1], b'\x00'])
        ptk = hmac.new(pmk, ptk_inputs, hashlib.sha1).digest()
        print("PTK : " + ptk.hex())
        
        return ptk

    def calculate_WPA_MIC(self, ptk, payload):
        MCI_Key = ptk[:16]
        MIC_raw = hmac.new(MCI_Key, payload, hashlib.sha1).hexdigest()
        MIC = MIC_raw[:32]
        print("MIC : " , MIC)
        
        return MIC , MIC_raw


    def run(self, mac_ap, mac_client, psk, ssid, anonce, snonce, payload):
        # config = WiFi_Object
        # mac_ap = bytes.fromhex((config.mac_ap).replace(":",""))
        # mac_client = bytes.fromhex((config.mac_client).replace(":",""))
        
        pmk = self.calculate_WPA_PMK(psk, ssid)
        ptk = self.calc_ptk(pmk, anonce, snonce, mac_ap, mac_client)
        MIC, MIC_raw = self.calculate_WPA_MIC(ptk, payload)
                
        return MIC, MIC_raw
    
    

def decrypt(packet, tk):

    addr1 = re.sub(":","",packet.addr1)
    addr2 = re.sub(":","",packet.addr2)
    print("addr1 : ", addr1)
    print("addr2 : ", addr2)

    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(packet.PN5,packet.PN4,packet.PN3,packet.PN2,packet.PN1,packet.PN0)
    print("PN : ",PN)
    # Priority Octet "00" 
    nonce = bytes.fromhex("00") + bytes.fromhex(addr2) + bytes.fromhex(PN)               
    TK = bytes.fromhex(tk) #TK
    print("密文  + 8bytes MIC : ", packet.data.hex()[:-16], packet.data.hex()[-16:])
    cipher_text = packet.data[:-8]
    # aad = fc + addr1 + addr2 + addr3 + sc
    
    # 真正解密过程
    cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
    cipher2 = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
    # cipher.update(AAD)
    plain_text = cipher.decrypt(cipher_text)
    
    p2 = LLC(plain_text)
    p2.payload.payload.show()       # 去掉LLC  / SNAP ,only arp
    print("明文 : ", plain_text.hex())            # 解密后明文
    
    
    mingwen = "aaaa0300000008060001080006040001e4029b5cfefe00000000000000000000c0a80477"
    miwen = cipher2.encrypt(bytes.fromhex(mingwen))
    print("再加密密文 : ", miwen.hex())     # 8edbee1d4210dcd61f47b9cd141915192f007f5189800e45392e33c551ed42259b8a8ca4
    
    
    mac_ap = bytes.fromhex("e4029b5cfefe")
    mac_client = bytes.fromhex("5a41201d26ed")
    psk = "smyl2021"
    ssid = "shuimuyulin-guest"
    anonce = bytes.fromhex("95436aa708728cc623eae215af5898dfaac67670b8a42add4db7ce2111947ed7")
    snonce = bytes.fromhex("9c5aa56d108e814a634f66139452c3cb44e85421f658e340d0b97bf5eb24f4bc")
    payload = bytes.fromhex(miwen.hex())
    
    calc_mic = Calc_MIC()
    mic , MIC_raw = calc_mic.run(mac_ap , mac_client, psk, ssid, anonce, snonce, payload)
    
    
    MIC = packet.data.hex().replace(miwen.hex(),"")
    print("MIC : ", MIC)        # 86762bc782931e25
    print("mic & MIC_raw : ", mic, MIC_raw)
    
    return mingwen



p = "000012002e480000006c8509c000eb01000088412c005a41201d26ede4029b5cfefeffffffffffff3000000002000020000000008edbee1d4210dcd61f47b9cd141915192f007f5189800e45392e33c551ed42259b8a8ca486762bc782931e25"
# 明文  :   aaaa0300000008060001080006040001e4029b5cfefe00000000000000000000c0a80477 

packet = RadioTap(bytes.fromhex(p))[Dot11]
tk = "66d1e91332d4735b4e7784804845161b"

mingwen = decrypt(packet, tk)

