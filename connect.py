import multiprocessing
from scapy.all import *
 
from wifi_inject_utils import Monitor

class WiFi_Object:
    def __init__(self, iface, ssid, psk, mac_ap, mac_client, anonce, snonce, payload, real_MIC):
        self.iface = iface
        self.ssid = ssid
        self.psk = psk
        self.mac_ap = mac_ap
        self.mac_client = mac_client
        self.ff_mac = "ff:ff:ff:ff:ff:ff"
        self.anonce = bytes.fromhex(anonce)
        self.snonce = bytes.fromhex(snonce)
        self.payload = bytes.fromhex(payload)
        self.real_MIC = real_MIC

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
            addr3=self.bssid) / Dot11Auth(
                algo=0, seqnum=0x0001, status=0x0000)
 
        packet.show()
 
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
            addr3=self.bssid)
        packet /= Dot11AssoReq(cap=0x1411, listen_interval=0x0001) 
        packet /= Dot11Elt(ID=0, info="{}".format(ssid))
        # packet /=  Dot11Elt(bytes.fromhex("30160100000fac040100000fac040100000fac023c000000"))
        packet /=  Dot11EltRSN(
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
        
        packet.show()
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



def main():      
    #   addr1     =   (RA=DA)  目的地址
    #   addr2     =   (TA=SA)  中间人
    #   addr3     =   (BSSID/STA)   AP/Client  源地址
    mtk9271au_1_smylguest = WiFi_Object(
        iface = "wlan0mon",
        ssid = "shuimuyulin-guest", 
        psk = "smyl2021",       
        mac_ap = "5A:41:20:1D:26:ED",    
        mac_client = "00:1d:43:20:19:2d",        # 00:1d:43:20:19:2d , mt7921au 第一块
        anonce = "", 
        snonce = "", 
        payload = (""),
        real_MIC = ""
        )
    mtk9271au_1_ztkj = WiFi_Object(
        iface = "wlan1mon",
        ssid = "ztkj", 
        psk = "ztkj123456",         # 假密码
        mac_ap = "20:6b:e7:a3:fc:a0",        # 20:6b:e7:a3:fc:a0  , ztkj 
        mac_client = "00:1d:43:20:19:2d",        # 00:1d:43:20:19:2d , mt7921au 第一块
        anonce = "", 
        snonce = "", 
        payload = (""),
        real_MIC = ""
        )
    
    config = mtk9271au_1_ztkj        # 改这里即可连接到不同wifi
    
    monitor_ifc = config.iface
    sta_mac = config.mac_client
    bssid = config.mac_ap        
    conf.iface = monitor_ifc
 
    # mac configuration per command line arguments, MACs are converted to
    # always use lowercase
    mon_ifc = Monitor(monitor_ifc, sta_mac.lower(), bssid.lower())
 
    connection = ConnectionPhase(mon_ifc, sta_mac, bssid)
    connection.send_authentication()
    if connection.state == "Authenticated":
        print("STA is authenticated to the AP!")
    else:
        print("STA is NOT authenticated to the AP!")
    time.sleep(1)
    connection.send_assoc_request(ssid=config.ssid)
 
    if connection.state == "Associated":
        print("STA is connected to the AP!")
    else:
        print("STA is NOT connected to the AP!")
        return 0
        
    eapol_1_packet = sniff(iface=config.iface, filter='ether proto 0x888e', prn=lambda x: x.summary(), count=1, store=1)
    
    print(eapol_1_packet)

    eapol_1_layer = eapol_1_packet[0].payload.payload.payload.payload
    eapol_1_layer.display()
    
    # 提取 anonce
    hexsteam = bytes(eapol_1_layer).hex()
    print(hexsteam)
    ANonce = hexsteam[34:98]
    print(ANonce)

    # 计算 MIC
    SNonce = scapy.randstring(32).hex()     # 发送时 bytes.fromhex(Nonce)
    
    # 发送 MIC
        
if __name__ == "__main__":
    sys.exit(main())
    
    
    
    
    
    
"""
# 00:1d:43:20:19:2d         mt7921au 第一块
# 00:a1:b0:79:03:f6         Ralink 3070 第一块
# 00:26:f2:88:6c:8a         netgear wn111 v2
"""