import multiprocessing
from scapy.all import *
from scapy.contrib.wpa_eapol import *
import binascii
import hashlib, hmac, sys, struct
from Crypto.Cipher import AES

from utils_wifi_inject import Monitor, RSN
from utils_wifi_crypt import Calc_MIC, GTKDecrypt, Generate_Plain_text

class WiFi_Object:
    def __init__(self, iface, ssid, psk, mac_ap="", mac_client="", anonce="", snonce="", payload="", mic=""):
        self.iface:str  = iface
        self.ssid:str  = ssid
        self.psk:str  = psk
        self.mac_ap:str  = mac_ap
        self.mac_client:str  = mac_client
        self.ff_mac:str  = "ff:ff:ff:ff:ff:ff"
        self.anonce:bytes = bytes.fromhex(anonce)
        self.snonce:bytes = bytes.fromhex(snonce)
        self.payload:bytes = bytes.fromhex(payload)
        self.mic:str = "0" * 32
        self.pmk:str = "0" * 40
        self.ptk:str = "0" * 40
        self.encrypt_msg:bytes = "0" * 56


class ConnectionPhase:
    """
    Establish a connection to the AP via the following commands
    """
 
    def __init__(self, monitor_ifc, sta_mac, bssid):
        self.state = "Not Connected"
        self.monitor = monitor_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
 
    def send_authentication(self):
        """
        Send an Authentication Request and wait for the Authentication Response.
        Which works if the user defined Station MAC matches the one of the
        wlan ifc itself.
 
        :return: -
        """
        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid,
            SC=0 ) / Dot11Auth(
                algo=0, seqnum=0x0001, status=0x0000)
 
        # packet.show()
 
        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.monitor.search_auth,
            args=(result_queue, ))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.monitor.send_packet,
            args=(packet, ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Authenticated"
 
    def send_assoc_request(self, ssid, rsn_info):
        """
        Send an Association Request and wait for the Association Response.
        Which works if the user defined Station MAC matches the one of the
        wlan ifc itself.
 
        :param ssid: Name of the SSID (ESSID)
        :return: -
        """
        if self.state != "Authenticated":
            print("Wrong connection state for Association Request: {0} "
                  "- should be Authenticated".format(self.state))
            return 1
 
        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid,
            SC=16)
        packet /= Dot11AssoReq(
                                cap='short-slot+res12+ESS+privacy+short-preamble', 
                                listen_interval=0x0001)
        packet /= Dot11Elt(ID=0, info="{}".format(ssid))
        packet /=  rsn_info
        #  RadioTap / Dot11 / Dot11AssoReq / Dot11Elt(ssid) /  Dot11EltRSN / Dot11EltVendorSpecific
        
        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.monitor.search_assoc_resp,
            args=(result_queue,))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.monitor.send_packet,
            args=(packet, "AssoReq", ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Associated"
        
    
class eapol_handshake():
    def __init__(self, DUT_Object, rsn_info):
        self.config = DUT_Object
        self.eapol_3_found = False    
        self.rsn_info = rsn_info
    
    def run(self):
        
        # Key (Message 1 of 4)
        print("\n-------------------------\nKey (Message 1 of 4): ")
        # 遗留问题：可能捕获到别人协商过程的eapol包
        eapol_p1 = sniff(iface=self.config.iface, 
                         lfilter=lambda r: (r.haslayer(EAPOL) and (r.getlayer(WPA_key).key_info  == 138)) , 
                         count=1, store=1, timeout=2)
        if len(eapol_p1) > 0:
            print("成功捕获到 EAPOL Message 1 of 4 ")
        else:
            print("未成功捕获到符合条件的 EAPOL Message 1 of 4 ")
            sys.exit(1)
        # # 提取 802.11 层 sequence
        # dot11_seq = eapol_p1[0].payload.SC

        # eapol_1_layer = eapol_p1[0].payload.payload.payload.payload   
        #                       RadioTap / Dot11 / LLC    / SNAP / EAPOL EAPOL-Key + **Raw**
        eapol_1_packet = eapol_p1[0][EAPOL]

        replay_counter = eapol_1_packet[WPA_key].replay_counter
        # 提取 anonce
        self.config.anonce = eapol_1_packet[WPA_key].nonce
        print("ANonce , ", (self.config.anonce).hex())
        
        
        # Key (Message 2 of 4)
        print("\n-------------------------\nKey (Message 2 of 4): ")
        # 计算 MIC
        self.config.snonce = randstring(32)
        eapol_2 = EAPOL(version=1, type=3, len=119) / WPA_key(
                        descriptor_type=2,
                        key_info=0x10a,
                        replay_counter=replay_counter,     # 和key 1 匹配, 用于匹配发送的每对消息，ap 每次重传它的包都会递增counter。
                        nonce=self.config.snonce,
                        wpa_key_length = 24,
                        wpa_key=self.rsn_info) 
        print("eapol_2_blank : ", bytes(eapol_2).hex())
        self.config.payload = bytes(eapol_2)

        calc_mic = Calc_MIC()
        self.config.pmk, self.config.ptk, self.config.mic = calc_mic.run(self.config)
        print(bytes.fromhex(self.config.mic))
        eapol_2[WPA_key].wpa_key_mic = bytes.fromhex(self.config.mic)
        
        eapol_2_packet = Dot11(
                                type=2, 
                                subtype=8, 
                                FCfield=1, 
                                addr1=self.config.mac_ap,
                                addr2=self.config.mac_client, 
                                addr3=self.config.mac_ap, 
                                SC=32 )  / Dot11QoS() / LLC() / SNAP() / eapol_2
        # eapol_2_packet.show()
        send(eapol_2_packet, iface = self.config.iface)
        
        # Key (Message 3 of 4)
        print("\n-------------------------\nKey (Message 3 of 4): ")
        
        result = sniff(iface=self.config.iface, 
                         lfilter=lambda r: (r.haslayer(EAPOL) and (r.getlayer(WPA_key).key_info  == 5066 )) ,
                         store=1, count=1,
                         timeout=1)
        # print(result)
        if len(result) > 0:
            print("成功捕获到 EAPOl Message 3 of 4")
        else:
            print("未成功捕获到符合条件的 EAPOL Message 3 of 4 ")
            sys.exit(1)
        eapol_3_packet = result[-1]
        # eapol_3_sequence = eapol_3_packet.payload.SC
        self.config.encrypt_msg = eapol_3_packet[WPA_key].wpa_key
        replay_counter = eapol_3_packet[WPA_key].replay_counter
        print("Encrypt Msg : ", self.config.encrypt_msg)
        
        # 解密出 gtk
        gtk_decrypt = GTKDecrypt(self.config)
        gtk , tk = gtk_decrypt.get_gtk()
        print("GTK : ", gtk)
        print("TK : ", tk)
        
        # Key (Message 4 of 4)
        print("\n-------------------------\nKey (Message 4 of 4): ")
        eapol_4 = EAPOL(version=1, type=3, len =95) / WPA_key(
                                                                descriptor_type=2, 
                                                                key_info=0x30a, 
                                                                replay_counter = replay_counter # 和key 3 匹配, 用于匹配发送的每对消息。
                                                                )
        self.config.payload = bytes(eapol_4)
        calc_mic2 = Calc_MIC()
        pmk, ptk, MIC_2 = calc_mic2.run(self.config)
        print(self.config.payload.hex())
        print(MIC_2)
        eapol_4[WPA_key].wpa_key_mic = bytes.fromhex(MIC_2)
        eapol_4_packet = Dot11(
            type=2, 
            subtype=8,   
            FCfield=1,      
            addr1=self.config.mac_ap,
            addr2=self.config.mac_client, 
            addr3=self.config.mac_ap, 
            SC=48)  / Dot11QoS() / LLC() / SNAP() / eapol_4
        # eapol_4_packet.show()
        send(eapol_4_packet, iface = self.config.iface)
    
        return tk
    




def main():      

    smyl = WiFi_Object(
        iface = "wlan0mon",
        ssid = "shuimuyulin", 
        psk = "smyl2021x7s3",       
        mac_ap = "58:41:20:FD:26:ED",           # smyl
        mac_client = "00:1d:43:20:19:2d",        # 00:1d:43:20:19:2d , mt7921au 第一块
        anonce = "", 
        snonce = "", 
        payload = ("")
        )
    smylguest = WiFi_Object(
        iface = "wlan0mon",
        ssid = "shuimuyulin-guest", 
        psk = "smyl2021",       
        mac_ap = "5a:41:20:1d:26:ed",           #
        mac_client = "00:1d:43:20:19:2d",        # 00:1d:43:20:19:2d , mt7921au 第一块
        anonce = "", 
        snonce = "", 
        payload = ("")
        )
    xiaom_hotspot = WiFi_Object(
        iface = "wlan0mon",
        ssid = "testwifi", 
        psk = "99999999",       
        mac_ap = "F6:71:82:F6:32:19",           # xiaomi hotspot
        mac_client = "00:1d:43:20:19:2d",        # mt7921au 第一块
        # mac_client = "00:a1:b0:79:03:f6",        # rt3070 第一块
        anonce = "", 
        snonce = "", 
        payload = ("")
        )
    
    
    config = smyl        # 改这里即可连接到不同wifi
    
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
    
