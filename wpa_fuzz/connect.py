import multiprocessing
from scapy.all import *
from pbkdf2 import PBKDF2
import binascii
import hashlib, hmac, sys, struct
 
from wifi_inject_utils import Monitor, Calc_MIC

class WiFi_Object:
    def __init__(self, iface, ssid, psk, mac_ap="", mac_client="", anonce="", snonce="", payload="", mic=""):
        self.iface = iface
        self.ssid = ssid
        self.psk = psk
        self.mac_ap = mac_ap
        self.mac_client = mac_client
        self.ff_mac = "ff:ff:ff:ff:ff:ff"
        self.anonce = bytes.fromhex(anonce)
        self.snonce = bytes.fromhex(snonce)
        self.payload = bytes.fromhex(payload)
        self.mic = "00000000000000000000000000000000"

def rsn():
    RSN = Dot11EltRSN(
            len=22,
            group_cipher_suite=RSNCipherSuite(),
            nb_pairwise_cipher_suites=1,
            pairwise_cipher_suites=[RSNCipherSuite()],
            nb_akm_suites=1,
            akm_suites=[AKMSuite(suite=2)], # 重要
            mfp_capable=0,
            mfp_required=0 ,
            gtksa_replay_counter=3 ,
            ptksa_replay_counter=3
            )
    RSN = bytes(RSN).hex()
    return RSN

class ConnectionPhase:
    """
    Establish a connection to the AP via the following commands
    """
 
    def __init__(self, monitor_ifc, sta_mac, bssid):
        self.state = "Not Connected"
        self.mon_ifc = monitor_ifc
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
            target=self.mon_ifc.search_auth,
            args=(result_queue, ))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet, ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Authenticated"
 
    def send_assoc_request(self, ssid):
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
        # packet /= Dot11AssoReq(cap=0x1411, listen_interval=0x0001) 
        packet /= Dot11AssoReq(cap=0x0000, listen_interval=0x0001) 
        packet /= Dot11Elt(ID=0, info="{}".format(ssid))
        # packet /=  Dot11Elt(bytes.fromhex("30160100000fac040100000fac040100000fac023c000000"))
        packet /=  Dot11EltRSN(
            len=22,
            group_cipher_suite=RSNCipherSuite(),
            nb_pairwise_cipher_suites=1,
            pairwise_cipher_suites=[RSNCipherSuite()],
            nb_akm_suites=1,
            akm_suites=[AKMSuite(suite=2)], # 重要
            mfp_capable=0,
            mfp_required=0 ,
            gtksa_replay_counter=3 ,
            ptksa_replay_counter=3
            )
    
        

        #  RadioTap / Dot11 / Dot11AssoReq / Dot11Elt(ssid) /  Dot11EltRSN / Dot11EltVendorSpecific
        
        # packet.show()
        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_assoc_resp,
            args=(result_queue,))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet, "AssoReq", ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Associated"
            
    def deauth(self):
        Dot11Deauth(reason=7)

    def eapol_handshake(self):
        sniff(iface=config.iface, filter='ether proto 0x888e', prn=lambda x: x.summary(), count=1, store=1)
        
    
class eapol_handshake():
    def __init__(self, DUT_Object):
        self.config = DUT_Object
        
    
    def run(self):
        
        # Key (Message 1 of 4)
        print("\n-------------------------\nKey (Message 1 of 4): ")
        eapol_1_packet = sniff(iface=self.config.iface, filter='ether proto 0x888e', prn=lambda x: x.summary(), count=1, store=1, timeout=1)
        
        # print(eapol_1_packet)

        eapol_1_layer = eapol_1_packet[0].payload.payload.payload.payload   
        #                       RadioTap / Dot11 / LLC    / SNAP / EAPOL EAPOL-Key / **Raw**
        # # 提取 802.11 层 sequence
        eapol_1_sequence = eapol_1_packet[0].payload.SC
        # 提取 anonce
        hexsteam = bytes(eapol_1_layer).hex()
        # print(hexsteam)
        self.config.anonce = bytes.fromhex(hexsteam[34:98])
        print("ANonce , ", (self.config.anonce).hex())
        
        # Key (Message 2 of 4)
        print("\n-------------------------\nKey (Message 2 of 4): ")
        # 计算 MIC
        self.config.snonce = randstring(32)     # 发送时 bytes.fromhex(Nonce)
        RSN = rsn()
        eapol_2_blank = "0103007702010a00000000000000000001" + (self.config.snonce).hex() + "0000000000000000000000000000000000000000000000000000000000000000" + self.config.mic + "0018" + RSN
        # print("eapol_2_blank", eapol_2_blank)
        self.config.payload = bytes.fromhex(eapol_2_blank)

        calc_mic = Calc_MIC()
        self.config.mic = calc_mic.run(self.config)
        eapol_2_full = "0103007702010a00000000000000000001" + (self.config.snonce).hex() +"0000000000000000000000000000000000000000000000000000000000000000" + self.config.mic + "0018" + RSN
        # print("eapol_2_full: ",eapol_2_full)
        t = EAPOL(bytes.fromhex(eapol_2_full))
        # print(bytes(t).hex())
        # t.display()
        
        
        eapol_2_packet = Dot11(
            type=2, 
            subtype=8, 
            FCfield=1, 
            addr1=self.config.mac_ap,
            addr2=self.config.mac_client, 
            addr3=self.config.mac_ap, 
            SC=32 )  / Dot11QoS() / LLC() / SNAP() / t
        # eapol_2_packet.show()
        send(eapol_2_packet, iface = self.config.iface)
        
        # Key (Message 3 of 4)
        print("\n-------------------------\nKey (Message 3 of 4): ")
        eapol_3_packet = sniff(iface=self.config.iface, filter='ether proto 0x888e', prn=lambda x: x.summary(), count=1, store=1, timeout=1)[0]
        # eapol_3_packet.show()
        eapol_3_sequence = eapol_3_packet.payload.SC
        print("Encrypt Msg : ", bytes(eapol_3_packet.payload.payload.payload.payload).hex())
        
        # Key (Message 4 of 4)
        print("\n-------------------------\nKey (Message 4 of 4): ")
        self.config.payload = bytes.fromhex("0103005f02030a00000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009f21ad3b5ec5adb6bfeb41b1d7a54d860000".replace("9f21ad3b5ec5adb6bfeb41b1d7a54d86","00000000000000000000000000000000"))
        MIC_2 = calc_mic.run(self.config)
        # print("MIC_2 : ", MIC_2)
        eapol_4_full = "0103005f02030a00000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009f21ad3b5ec5adb6bfeb41b1d7a54d860000".replace("9f21ad3b5ec5adb6bfeb41b1d7a54d86",MIC_2)
        t = EAPOL(bytes.fromhex(eapol_4_full))
        eapol_4_packet = Dot11(
            type=2, 
            subtype=8,   
            FCfield=1,
            addr1=self.config.mac_ap,
            addr2=self.config.mac_client, 
            addr3=self.config.mac_ap, 
            SC=48)  / Dot11QoS() / LLC() / SNAP() / t
        # eapol_4_packet.show()
        send(eapol_4_packet, iface = self.config.iface)