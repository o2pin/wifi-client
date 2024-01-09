#!/usr/bin/python3
# -*- coding: utf-8 -*-​


import binascii
import hashlib, hmac
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
import pyaes

from scapy.all import LLC, SNAP, ARP, IP, UDP, DHCP, BOOTP, struct, raw, Dot11QoS

class Calc_MIC():
    '''
    For WPA1 and WPA2
    '''
    def __init__(self, wpa_keyver='WPA2') -> None:
        self.wpa_keyver = wpa_keyver
        
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

    def calc_ptk(self, pmk, anonce, snonce, mac_ap, mac_cl):
        macs = self.min_max(mac_ap, mac_cl)
        nonces = self.min_max(anonce, snonce)
        ptk_inputs = b''.join([b'Pairwise key expansion\x00', macs[0], macs[1], nonces[0], nonces[1], b'\x00'])
        ptk = hmac.new(pmk, ptk_inputs, hashlib.sha1).digest()
        # ptk = bytes(ptk, encoding='utf-8')
        print("PTK : " + ptk.hex())
        
        
        return ptk

    def calculate_WPA_MIC(self, ptk, payload):
        MIC_Key = ptk[:16]
        if self.wpa_keyver == 'WPA1':
            MIC = hmac.new(MIC_Key,payload ,hashlib.md5).digest()
            print("MIC : " , MIC[:16].hex())
            mic = MIC[:16].hex()
        else:
            MIC = hmac.new(MIC_Key,payload ,hashlib.sha1).digest()
            print("MIC : " , MIC.hex())
            mic = MIC.hex()
        return mic


    def run(self, WiFi_Object):
        config = WiFi_Object
        # print(config.__dict__)
        mac_ap = bytes.fromhex((config.mac_ap).replace(":",""))
        mac_sta = bytes.fromhex((config.mac_sta).replace(":",""))
        
        pmk = self.calculate_WPA_PMK(config.psk, config.ssid)
        WiFi_Object.pmk = pmk
        ptk = self.calc_ptk(pmk, config.anonce, config.snonce, mac_ap, mac_sta)
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
        mac_sta = bytes.fromhex((self.config.mac_sta).replace(":",""))
        macs = Calc_MIC.min_max(self, mac_ap, mac_sta)
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
                            )
            # print(TK , nonce.hex())
            ip = IP(dst="255.255.255.255", src = "0.0.0.0")
            udp = UDP(sport = 68, dport = 67)
            
            Plain_text = LLC() / SNAP() / ip / udp / dhcp_layer
        elif type == "arp"    :
            arp = ARP(hwsrc="00:1d:43:20:19:2d", psrc="192.168.4.222", hwdst="00:00:00:00:00:00", pdst="192.168.4.1")
            Plain_text = LLC() / SNAP() / arp
        else:
            print("Wrong type ")
        return Plain_text
    
 

class CCMPCrypto:
    # @staticmethod
    # def ccmp_get_nonce(packet):
    #     PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(packet.PN5,packet.PN4,packet.PN3,packet.PN2,packet.PN1,packet.PN0)
    #     print("PN : ",PN)
    #     # Priority Octet "00" 
    #     nonce = bytes.fromhex("00") + bytes.fromhex(packet[Dot11].addr2) + bytes.fromhex(PN)  
        
    #     return nonce
    @staticmethod
    def ccmp_get_nonce(priority, addr, pn):
        """
        CCMP nonce = 1 byte priority, 6 byte sender addr, 6 byte PN.
        """
        nonce = bytes.fromhex(priority) + bytes.fromhex((addr).replace(":", "")) + bytes.fromhex(pn)
    
        return nonce
    
    @staticmethod
    def ccmp_get_aad(p, amsdu_spp=False):
        # 要求p是一个Dot11包
        # FC field with masked values
        fc = raw(p)[:2]
        fc = bytes([fc[0] & 0x8F, fc[1] & 0xC7])

        # Sequence number is masked, but fragment number is included
        sc = struct.pack("<H", p.SC & 0xF)

        addr1 = bytes.fromhex((p.addr1).replace(":", ""))
        addr2 = bytes.fromhex((p.addr2).replace(":", ""))
        addr3 = bytes.fromhex((p.addr3).replace(":", ""))
        aad = fc + addr1 + addr2 + addr3 + sc

        if Dot11QoS in p:
            if not amsdu_spp:
                # Everything except the TID is masked
                aad += struct.pack("<H", p[Dot11QoS].TID)
            else:
                # TODO: Mask unrelated fields
                aad += bytes(raw(p[Dot11QoS])[:2])

        return aad
    
    @staticmethod
    def cbc_mac(key, plaintext, aad, nonce, iv=b"\x00" * 16, mac_len=8):
        '''
        # 使用方法举例
        # MIC = CCMPCrypto.cbc_mac(tk, plaintext, aad, nonce)
        # plaintext 结构举例 LLC / SNAP / ARP
        '''
        assert len(key) == len(iv) == 16  # aes-128
        assert len(nonce) == 13
        iv = int.from_bytes(iv, byteorder="big")
        assert len(aad) < (2**16 - 2**8)

        q = L = 2
        Mp = (mac_len - 2) // 2
        assert q == L
        has_aad = len(aad) > 0
        flags = 64 * has_aad + 8 * Mp + (q - 1)
        b_0 = bytes([flags]) + nonce + len(plaintext).to_bytes(2, byteorder='big')
        assert len(b_0) == 16

        a = len(aad).to_bytes(2, byteorder='big') + aad
        if len(a) % 16 != 0:
            a += b"\x00" * (16 - len(a) % 16)
        blocks = b_0 + a
        blocks += plaintext

        if len(blocks) % 16 != 0:
            blocks += b"\x00" * (16 - len(blocks) % 16)

        encrypt = pyaes.AESModeOfOperationECB(key).encrypt
        prev = iv
        for i in range(0, len(blocks), 16):
            inblock = int.from_bytes(blocks[i : i + 16], byteorder="big")
            outblock = encrypt(int.to_bytes(inblock ^ prev, length=16, byteorder="big"))
            prev = int.from_bytes(outblock, byteorder="big")

        xn = bytes([q - 1]) + nonce + b"\x00" * L
        ctr_nonce = int.from_bytes(xn, byteorder="big")
        xctr = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(ctr_nonce)).encrypt
        xs0 = xctr(b"\x00" * 16)
        s_0 = int.from_bytes(xs0, byteorder="big")

        return int.to_bytes(s_0 ^ prev, length=16, byteorder="big")[:mac_len]