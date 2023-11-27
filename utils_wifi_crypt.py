#!/usr/bin/python3
# -*- coding: utf-8 -*-​

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
        print("minx_max type : ",type(mac_ap))
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
        print("MIC : " + MIC)
        
        return MIC


    def run(self, WiFi_Object):
        config = WiFi_Object
        mac_ap = bytes.fromhex((config.mac_ap).replace(":",""))
        mac_client = bytes.fromhex((config.mac_client).replace(":",""))
        
        pmk = self.calculate_WPA_PMK(config.psk, config.ssid)
        WiFi_Object.pmk = pmk
        ptk = self.calc_ptk(pmk, config.anonce, config.snonce, mac_ap, mac_client)
        MIC = self.calculate_WPA_MIC(ptk, config.payload)
                
        return pmk, ptk, MIC


class GTKDecrypt():
    def __init__(self, WiFi_Object):
        self.config = WiFi_Object
        
    def min_max(self, a, b):
        if len(a) != len(b): raise 'Unequal byte string lengths' 
        for entry in list(zip( list(bytes(a)), list(bytes(b)) )):
            if entry[0] < entry[1]: return (a, b)
            elif entry[1] < entry[0]: return (b, a)
        return (a, b)
    
    def prf_80211i(self, K, A, B, Len):
        R = b""
        i = 0
        while i <= ((Len + 159) / 160):
            hmac_result = hmac.new(K, A + bytes.fromhex("00") + B + bytes([i]), hashlib.sha1).digest()
            i += 1
            R += hmac_result
        return binascii.hexlify(R).decode()[:128]    
    
    def generate_ptk_kek(self):
        mac_ap = bytes.fromhex((self.config.mac_ap).replace(":",""))
        mac_client = bytes.fromhex((self.config.mac_client).replace(":",""))
        macs = Calc_MIC.min_max(self, mac_ap, mac_client)
        nonces = self.min_max(self.config.anonce, self.config.snonce)
        ptk = self.prf_80211i(self.config.pmk, b"Pairwise key expansion", macs[0] + macs[1] + nonces[0] + nonces[1], 384)

        # kck = ptk[:32]
        kek = ptk[32:64]
        tk = ptk[64:96]
        # mic_tx = ptk[96:112]
        # mic_rx = ptk[112:]
        
        return ptk,  kek, tk
    
    def get_gtk(self):
        
        ptk , kek , tk = self.generate_ptk_kek()
        kek = bytes.fromhex(kek)
        encrypt_msg = self.config.encrypt_msg
        print("生成gtk: ", kek, encrypt_msg)
        gtk = aes_key_unwrap(kek, encrypt_msg).hex()[60:-4]
        
        return gtk, tk


class Generate_Plain_text():
    def Plain_text(self, type : str):
        if type == "dhcp":
            dhcp_layer = BOOTP( 
                            op=1,
                            htype=1,
                            hlen=6 ,
                            hops=0 ,
                            xid=1234 ,
                            secs=0 ,
                            flags= b"0000",
                            ciaddr="0.0.0.0" ,
                            yiaddr="0.0.0.0" ,
                            siaddr="0.0.0.0" ,
                            giaddr="0.0.0.0" ,
                            chaddr=b"001d4320192d" ,
                            sname=b'' * 64 ,
                            file=b'' * 128 ,
                            options=b'63825363', 
                            # options=[message-type=request client_id='\x01\x00\x1dC \x19-' requested_addr=192.168.4.119 hostname=b'bichenshao-pc' client_FQDN=b'\x00\x00\x00bichenshao-pc' vendor_class_id='MSFT 5.0' param_req_list=[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252] end ........]
                            )
            print(TK , nonce.hex())
            ip = IP(dst="255.255.255.255", src = "0.0.0.0")
            udp = UDP(sport = 68, dport = 67)
            
            Plain_text = LLC() / SNAP() / ip / udp / dhcp_layer
        elif type == "arp"    :
            arp = ARP(hwsrc="00:1d:43:20:19:2d", psrc="0.0.0.0", hwdst="00:00:00:00:00:00", pdst="192.168.4.119")
            Plain_text = LLC() / SNAP() / arp
        else:
            print("Wrong type ")
        return Plain_text