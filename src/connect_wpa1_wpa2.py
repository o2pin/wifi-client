import logging
import multiprocessing
from scapy.layers.dot11 import (
    Dot11Auth,
    Dot11Deauth,
    Dot11,
    RadioTap,
    Dot11AssoReq,
    Dot11Elt,
    Dot11EltRSN,
    RSNCipherSuite,
    AKMSuite,
    Dot11QoS ,
    LLC ,
    Dot11CCMP
    )
from scapy.layers.l2    import SNAP
from scapy.all import *
from scapy.contrib.wpa_eapol import *
import sys
from Crypto.Cipher import AES

from .utils_wifi_inject import Monitor, RSN, TKIP_info
from .utils_wpa1_wpa2_crypt import Calc_MIC, GTKDecrypt
from .utils_wpa2_arp_dhcp import ONCE_REQ

from socket_hook_py import sendp, send, sniff 


'''
TODO:
    1. WPA1 EAPOL m3 中 gtk 解密
    2. 将 WPA3 也合并进来
    3. 响应路由器在线设备查询, 需要实现不同加密报文场景，如 DHCP Req / IGMP Replay 等
'''

FORMAT = '%(asctime)s::%(filename)s:%(funcName)s:%(lineno)d ---- %(message)s'
logging.basicConfig(level = logging.DEBUG, format=FORMAT)

class WiFi_Object:
    def __init__(self, iface, ssid, psk, mac_ap="", mac_sta="", anonce="", snonce="", payload="", mic="", wpa_keyver='WPA2'):
        self.iface:str  = iface
        self.ssid:str  = ssid
        self.psk:str  = psk
        self.mac_ap:str  = mac_ap
        self.mac_sta:str  = mac_sta
        self.ff_mac:str  = "ff:ff:ff:ff:ff:ff"
        self.anonce:bytes = bytes.fromhex(anonce)
        self.snonce:bytes = bytes.fromhex(snonce)
        self.payload:bytes = bytes.fromhex(payload)
        self.mic:str = "0" * 32
        self.pmk:str = "0" * 40
        self.ptk:str = "0" * 40
        self.encrypt_msg:bytes = "0" * 56
        self.wpa_keyver:str = wpa_keyver        # WPA1 or WPA2


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
            # 需要先等待sniff监控上数据包, 否则多个进程的时序没有保证, 可能丢失Auth Response包？？
            time.sleep(0.1)
        for job in jobs:
            job.join()

        if result_queue.get():
            self.state = "Authenticated"

    def send_assoc_request(self, ssid, vendor_info):
        """
        Send an Association Request and wait for the Association Response.
        Which works if the user defined Station MAC matches the one of the
        wlan ifc itself.

        :param ssid: Name of the SSID (ESSID)
        :return: -
        """
        if self.state != "Authenticated":
            logging.debug(f"Wrong connection state for Association Request: {self.state} "
                  "- should be Authenticated")
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
        packet /=  vendor_info
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
            # 需要先等待sniff监控上数据包, 否则多个进程的时序没有保证, 可能丢失Assosi Response包？？
            time.sleep(0.1)
        for job in jobs:
            job.join()

        if result_queue.get():
            self.state = "Associated"

class eapol_handshake():
    def __init__(self, DUT_Object, vendor_info):
        self.config = DUT_Object
        self.eapol_3_found = False
        self.vendor_info = vendor_info
        
        if self.config.wpa_keyver == 'WPA1':
            self.eapkey_info = {
                'm1_keyinfo':0x0089,   # dec: 137
                'm2_keyinfo':0x0109,
                'm3_keyinfo':0x01c9,
                'm4_keyinfo':0x0109,
                }
        else:
            self.eapkey_info = {        # WPA2
                'm1_keyinfo':0x008a,    # dec: 138
                'm2_keyinfo':0x010a,
                'm3_keyinfo':0x13ca,    # dec: 5066
                'm4_keyinfo':0x030a,
                }

    def run(self):
        # Key (Message 1 of 4)
        logging.info("\n-------------------------Key (Message 1 of 4): ")
        eapol_p1 = sniff(iface=self.config.iface,
                         lfilter=lambda r: (r.haslayer(Dot11) 
                                            and r[Dot11].addr1 == self.config.mac_sta 
                                            and r.haslayer(WPA_key) 
                                            and r.getlayer(WPA_key).key_info  == self.eapkey_info['m1_keyinfo']
                                            # and (r.getlayer(WPA_key).key_info  == 0x0089)) ,
                                            ) ,
                         count=1, store=1, timeout=2, 
                        #  prn = lambda x: logging.debug(x)
                         )
        if len(eapol_p1) > 0:
            logging.info("成功捕获到 EAPOL Message 1 of 4 ")
        else:
            logging.error("未成功捕获到符合条件的 EAPOL Message 1 of 4 ")
            sys.exit(1)
        # # 提取 802.11 层 sequence
        # dot11_seq = eapol_p1[0].payload.SC
        # eapol_1_layer = eapol_p1[0].payload.payload.payload.payload
        # RadioTap / Dot11 / LLC / SNAP / EAPOL EAPOL-Key + **Raw**
        eapol_1_packet = eapol_p1[0][EAPOL]
        replay_counter = eapol_1_packet[WPA_key].replay_counter
        # 提取 anonce
        self.config.anonce = eapol_1_packet[WPA_key].nonce
        logging.debug("ANonce {}".format((self.config.anonce).hex()))

        # Key (Message 2 of 4)
        logging.info("-------------------------Key (Message 2 of 4): ")
        # 计算 MIC
        self.config.snonce = randstring(32)
        eapol_2 = EAPOL(version=1, type=3, len=119) / WPA_key(
                        descriptor_type=254,
                        key_info=self.eapkey_info['m2_keyinfo'],
                        len=32,
                        replay_counter=replay_counter,     # 和key 1 匹配, 用于匹配发送的每对消息，ap 每次重传它的包都会递增counter。
                        nonce=self.config.snonce,
                        wpa_key_length = 24,
                        wpa_key=self.vendor_info)
        logging.debug(f"eapol_2_blank : {bytes(eapol_2).hex()}")
        self.config.payload = bytes(eapol_2)

        calc_mic = Calc_MIC(wpa_keyver=self.config.wpa_keyver)      # WPA1 or WPA2; default WPA2
        self.config.pmk, self.config.ptk, self.config.mic = calc_mic.run(self.config)
        eapol_2[WPA_key].wpa_key_mic = bytes.fromhex(self.config.mic)

        eapol_2_packet = Dot11(
                                type=2,
                                subtype=8,
                                FCfield=1,
                                addr1=self.config.mac_ap,
                                addr2=self.config.mac_sta,
                                addr3=self.config.mac_ap,
                                SC=32 )  / Dot11QoS() / LLC() / SNAP() / eapol_2
        # eapol_2_packet.show()
        send(eapol_2_packet, iface = self.config.iface, verbose=0)

        # Key (Message 3 of 4)
        logging.info("\n-------------------------Key (Message 3 of 4): ")

        result = sniff(iface=self.config.iface,
                         lfilter=lambda r: (r.haslayer(EAPOL) 
                                            and r.getlayer(WPA_key).key_info  == self.eapkey_info['m3_keyinfo']
                                            ) ,
                         store=1, count=1,
                         timeout=1)

        if len(result) > 0:
            logging.info("成功捕获到 EAPOl Message 3 of 4")
        else:
            logging.info("未成功捕获到符合条件的 EAPOL Message 3 of 4 ")
            sys.exit(1)
        eapol_3_packet = result[-1]
        # eapol_3_sequence = eapol_3_packet.payload.SC
        self.config.encrypt_msg = eapol_3_packet[WPA_key].wpa_key
        replay_counter = eapol_3_packet[WPA_key].replay_counter
        logging.debug(f"Encrypt Msg : {(self.config.encrypt_msg).hex()}")
        # print(f'{self.config.encrypt_msg.hex()}')

        ## 解密出 gtk
        if self.config.wpa_keyver == 'WPA2':
            gtk_decrypt = GTKDecrypt(self.config)
            gtk , tk = gtk_decrypt.get_gtk()
            logging.debug(f"GTK : {gtk}")
            logging.debug(f"TK : {tk}")

        # Key (Message 4 of 4)
        logging.info("\n-------------------------Key (Message 4 of 4): ")
        eapol_4 = EAPOL(version=1, type=3, len =95) / WPA_key(
                                                                descriptor_type=254,
                                                                key_info=self.eapkey_info['m4_keyinfo'],
                                                                len=32,
                                                                replay_counter = replay_counter # 和key 3 匹配, 用于匹配发送的每对消息。
                                                                )
        self.config.payload = bytes(eapol_4)
        calc_mic2 = Calc_MIC()
        pmk, ptk, MIC_m4 = calc_mic2.run(self.config)
        # logging.debug(self.config.payload.hex())
        # logging.debug(MIC_m4)
        eapol_4[WPA_key].wpa_key_mic = bytes.fromhex(MIC_m4)
        eapol_4_packet = Dot11(
            type=2,
            subtype=8,
            FCfield=1,
            addr1=self.config.mac_ap,
            addr2=self.config.mac_sta,
            addr3=self.config.mac_ap,
            SC=48)  / Dot11QoS() / LLC() / SNAP() / eapol_4
        # eapol_4_packet.show()
        send(eapol_4_packet, iface = self.config.iface, verbose=0)

        return tk
        # return 


def test(
        iface = "monwlan2",
        ssid = "testnetwork",
        psk = "passphrase",
        ap_mac = "02:00:00:00:00:00",
        sta_mac = "02:00:00:00:01:00",
        scene = 3,
        wpa_keyver= 'WPA2',
        router_ip = '192.168.4.1'
):
    config = WiFi_Object(
        iface = iface,
        ssid = ssid,
        psk = psk,
        mac_ap = ap_mac,
        mac_sta = sta_mac,
        anonce = "",
        snonce = "",
        payload = (""),
        wpa_keyver= wpa_keyver,
    )
    
    # logging.debug(config.__dict__)

    if config.wpa_keyver == 'WPA1':
        vendor_info = TKIP_info.gen_tkip_info()
    else:
        vendor_info = RSN.get_rsn_info()
    conf.iface = config.iface       # scapy.config.conf.iface
    monitor = Monitor(config.iface, config.mac_sta.lower(), config.mac_ap.lower())
    connectionphase_1 = ConnectionPhase(monitor, config.mac_sta, config.mac_ap)

    # 链路认证
    logging.info("\n-------------------------Link Authentication Request : ")
    connectionphase_1.send_authentication()

    if connectionphase_1.state == "Authenticated":
        logging.info("STA is authenticated to the AP!")
    else:
        logging.info("STA is NOT authenticated to the AP!")
        sys.exit(1)
    # 场景0 测试认证过程
    if scene == 0:
        sys.exit(0)

    # 链路关联
    logging.info("\n-------------------------Link Assocation Request : ")
    connectionphase_1.send_assoc_request(ssid=config.ssid, vendor_info=vendor_info)

    if connectionphase_1.state == "Associated":
        logging.info("STA is connected to the AP!")
    else:
        logging.info("STA is NOT connected to the AP!")
        sys.exit(1)
    # 场景1 测试关联过程
    if scene == 1:
        sys.exit(0)

    connectionphase_2 = eapol_handshake(DUT_Object=config, vendor_info=vendor_info)
    TK = connectionphase_2.run()
    logging.info("WiFi 协商完成!")
    
    # 场景2 测试密钥协商
    if scene == 2:
        sys.exit(0)

    # # 和 AP 加密通信
    if wpa_keyver== 'WPA2':
        we_will_send = 'ARP' # ARP or DHCP
        logging.info(f"\n-------------------------Send {we_will_send} Request : ")
        logging.info(f" TK : {TK}")
        setattr(config, 'TK', TK)
        
        encrypt_packet = ONCE_REQ.request_once(  config= config , req_type= we_will_send, router_ip=router_ip)
        
        sendp(RadioTap() / encrypt_packet, iface = config.iface, verbose=0)
        logging.info(f'We sent 1 {we_will_send} ! ')

if __name__ == "__main__":
    test()