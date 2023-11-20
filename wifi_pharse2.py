from pbkdf2 import PBKDF2
from scapy.all import *
import binascii
import hashlib, hmac, sys, struct


class WiFi_Object:
    def __init__(self, ssid, psk, mac_ap, mac_cl, anonce, snonce, payload, real_MIC):
        self.ssid = ssid
        self.psk = psk
        self.mac_ap = bytes.fromhex(mac_ap)
        self.mac_cl = bytes.fromhex(mac_cl)
        self.anonce = bytes.fromhex(anonce)
        self.snonce = bytes.fromhex(snonce)
        self.payload = bytes.fromhex(payload)
        self.real_MIC = real_MIC

class Calc_MIC():
    """
    4次EAPOL协议握手顺序 : 
        ap发送anonce
            client生成snonce
            client结合anonce、snonce、ssid、password 计算 mic
        client 发送 mic 和 anonce
            ap接收到mic和anonce
            ap校验mic
            ap通过校验
        ap 发送通信密钥的密文
            client接收到密文
            client解密得到GTK
        client 发送ACK，仅用作确认
    """
    
    def min_max(self, a, b):
        if len(a) != len(b): raise 'Unequal byte string lengths' 
        for entry in list(zip( list(bytes(a)), list(bytes(b)) )):
            if entry[0] < entry[1]: return (a, b)
            elif entry[1] < entry[0]: return (b, a)
        return (a, b)
    
    def calculate_WPA_PMK(self, psk, ssid):
        # pmk = PBKDF2(psk, ssid, 4096).read(32)
        pmk = hashlib.pbkdf2_hmac('sha1', psk.encode(), ssid.encode(), 4096, 32)
        print("PMK : " + pmk.hex())
        
        return pmk

    def calc_ptk(self, pmk, anonce, snonce, mac_ap, mac_cl):
        key_data = min(mac_ap, mac_cl) + max(mac_ap, mac_cl) + min(anonce,snonce) + max(anonce,snonce)
        # ptk = customPRF512(pmk, pke, key_data)
        macs = self.min_max(mac_ap, mac_cl)
        nonces = self.min_max(anonce, snonce)
        ptk_inputs = b''.join([b'Pairwise key expansion\x00', macs[0], macs[1], nonces[0], nonces[1], b'\x00'])
        ptk = hmac.new(pmk, ptk_inputs, hashlib.sha1).digest()
        # ptk = bytes(ptk, encoding='utf-8')
        print("PTK : " + ptk.hex())
        
        return ptk

    def calculate_WPA_MIC(self, ptk, payload):
        MCI_Key = ptk[:16]
        MIC_raw = hmac.new(MCI_Key, payload, hashlib.sha1).hexdigest()
        MIC = MIC_raw[:32]
        print("MIC : " + MIC)
        
        return MIC


    def main(self, WiFi_Object):
        

        
        config = WiFi_Object       # 改这里
        pmk = self.calculate_WPA_PMK(config.psk, config.ssid)
        ptk = self.calc_ptk(pmk, config.anonce, config.snonce, config.mac_ap, config.mac_cl)
        MIC_1 = self.calculate_WPA_MIC(ptk, config.payload)
        m4_mic = "28bffa440f189c2dfe06f2e3486f3b83"
        m4_payload = bytes.fromhex("010300970213ca00100000000000000002777f196229c576fda543ca0c5d3c96ac23bc4c67f6e8ea618966dbc7e0150654000000000000000000000000000000008392ba0000000000000000000000000000000000000000000000000000000000003804439acbbfc551b36a900fc19eef6655f6f371c7a7e54c11a3738aef32fdf42de0cd00ac6a91360fbac7efec0f745d1f6c38f4b665642542")
        MIC_2 = self.calculate_WPA_MIC(ptk, m4_payload)
        print("MIC_2 : " + MIC_2)
        MIC = None
        if config.real_MIC != "":
            if MIC_1 == config.real_MIC:
                print("\n MIC Success ")
                MIC = MIC_1
            else:
                print("\n MIC Error ")
            return MIC


def main():
    
    xiaomi2smylguest = WiFi_Object(
        ssid = "shuimuyulin-guest", 
        psk = "smyl2021", 
        mac_ap = "5A41201D26ED", 
        mac_cl = "a44bd50fa9af",        # a4:4b:d5:0f:a9:af
        anonce = "777f196229c576fda543ca0c5d3c96ac23bc4c67f6e8ea618966dbc7e0150654", 
        snonce = "b18c2b09d7bac11936ece756a9608fb4864374e688aabe89a1c2bdf8e1dbf41c", 
        payload = ("0103007502010a00000000000000000001b18c2b09d7bac11936ece756a9608fb4864374e688aabe89a1c2bdf8e1dbf41c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000"),
        real_MIC = "297aad39c9ab6d9cf30d91525da42816")
    
    sony2cisco = WiFi_Object(
        ssid = "ikeriri-5g", 
        psk = "wireshark", 
        mac_ap = ("500f807018d0"), 
        mac_cl = ("4040a75073db"), 
        anonce = ("15adf473164f43a34f211ebc34495b588af5b915c0dd4478f5fbc89d2f7bd0fa"), 
        snonce = ("1b9717293f9d9d6979d94b36dbc9d83418bbce09f72edc1e1ae4fd79821ffda4"), 
        payload = ("0103007502010a000000000000000000011b9717293f9d9d6979d94b36dbc9d83418bbce09f72edc1e1ae4fd79821ffda4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac023c00"),
        real_MIC = "2f8e7921e572afd75a7c898e625ffb43")


    """

    """
    DUT_Object = xiaomi2smylguest
    calc_mic = Calc_MIC()
    
    calc_mic.main(DUT_Object)

if __name__=="__main__":
    sys.exit(main())
