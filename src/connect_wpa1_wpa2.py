import logging, multiprocessing, time, sys
import hmac, hashlib
# import timeout_decorator
# from wrapt_timeout_decorator  import timeout as wrap_timeout
# import pysnooper
import asyncio

from scapy.layers.dot11 import (
    Dot11Auth,
    Dot11Deauth,
    Dot11ProbeResp,
    Dot11,
    RadioTap,
    Dot11AssoReq,
    Dot11Elt,
    Dot11QoS,
    Dot11TKIP,
    LLC,
    conf
    )
from scapy.layers.l2    import SNAP
from scapy.contrib.wpa_eapol import WPA_key, EAPOL
from scapy.utils import randstring, mac2str
from scapy.sendrecv import AsyncSniffer, sniff, send, sendp
from scapy.modules.krack.crypto import parse_data_pkt, build_TKIP_payload, build_MIC_ICV,ARC4_decrypt, ARC4_encrypt, customPRF512


from .utils_wifi_inject import Monitor, RSN, TKIP_info, ProbeReq
from .utils_wpa1_wpa2_crypt import Calc_MIC, GTKDecrypt
from .utils_wpa2_arp_dhcp import ONCE_REQ

from socket_hook_py import sendp, send, sniff , AsyncSniffer

# ----------------------- Utility ---------------------------------
'''
TODO:
    1. WPA1 EAPOL m3 中 gtk 解密
    2. 将 WPA3 也合并进来
    3. 响应路由器在线设备查询, 需要实现不同加密报文场景，如 DHCP Req / IGMP Replay 等
'''

class Scene:
    probeReq = 0
    auth = 1
    asso = 2
    four_way_handshake = 3
    wpa1_grouphandshake = 4
    talktoap = 5
    deauth = 6
    
FORMAT = "[%(filename)s:%(lineno)d] --- %(message)s"
logging.basicConfig(level = logging.DEBUG, format=FORMAT)

class WiFi_Object:
    def __init__(self, iface, ssid, psk, mac_ap="", mac_sta="", anonce="", snonce="", payload="", mic="", wpa_keyver='WPA2', timeout=1):
        self.iface:str  = iface
        self.ssid:str  = ssid
        self.psk:str  = psk
        self.mac_ap:str  = mac_ap
        self.mac_sta:str  = mac_sta
        self.wpa_keyver:str = wpa_keyver        # WPA1 or WPA2
        self.timeout = timeout
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

    def __init__(self, monitor_ifc, sta_mac, bssid, timeout=1):
        self.state = "Not Connected"
        self.monitor = monitor_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
        self.timeout = timeout

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
            args=(result_queue,))
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
    def __init__(self, DUT_Object, vendor_info, scene=3, timeout=1):
        self.config = DUT_Object
        self.eapol_3_found = False
        self.vendor_info = vendor_info
        self.scene = scene
        self.timeout = timeout
        
        if self.config.wpa_keyver == 'WPA1':
            self.eapkey_info = {
                'm1_keyinfo':0x0089,   # dec: 137
                'm2_keyinfo':0x0109,
                'm3_keyinfo':0x01c9,
                'm4_keyinfo':0x0109,
                'group1_keyinfo':0x0391,
                'group2_keyinfo':0x0311,
                }
        else:
            self.eapkey_info = {        # WPA2
                'm1_keyinfo':0x008a,    # dec: 138
                'm2_keyinfo':0x010a,
                'm3_keyinfo':0x13ca,    # dec: 5066
                'm4_keyinfo':0x030a,
                }

    async def run(self):
        # Key (Message 1 of 4)
        logging.info("-------------------------Key (Message 1 of 4): ")
        capt_eapol_p1 = AsyncSniffer(iface=self.config.iface,
                         lfilter=lambda r: (r.haslayer(Dot11) 
                                            and r[Dot11].addr1 == self.config.mac_sta 
                                            and r.haslayer(WPA_key) 
                                            and r.getlayer(WPA_key).key_info  == self.eapkey_info['m1_keyinfo']
                                            # and (r.getlayer(WPA_key).key_info  == 0x0089)) ,
                                            ) ,
                         stop_filter=lambda r: (r.haslayer(Dot11) 
                                            and r[Dot11].addr1 == self.config.mac_sta 
                                            and r.haslayer(WPA_key) 
                                            and r.getlayer(WPA_key).key_info  == self.eapkey_info['m1_keyinfo']
                                            # and (r.getlayer(WPA_key).key_info  == 0x0089)) ,
                                            ) ,
                         count=1, store=1, 
                         timeout=self.timeout, 
                        #  prn = lambda x: logging.debug(x)
                         )
        capt_eapol_p1.start()
        await asyncio.sleep(0.05)
        capt_eapol_p1.join()
        eapol_p1 = capt_eapol_p1.results
        
        if len(eapol_p1) > 0:
            logging.info("成功捕获到 EAPOL Message 1 of 4 ")
        else:
            logging.error("未成功捕获到符合条件的 EAPOL Message 1 of 4 ")
            sys.exit(1)
        # # 提取 802.11 层 sequence
        # dot11_seq = eapol_p1[0].payload.SC
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
        # logging.debug(f"eapol_2_blank : {bytes(eapol_2).hex()}")
        self.config.payload = bytes(eapol_2)

        calc_mic = Calc_MIC(wpa_keyver=self.config.wpa_keyver)      # WPA1 or WPA2; default WPA2
        self.config.pmk, self.config.ptk, self.config.mic = calc_mic.run(self.config)
        eapol_2[WPA_key].wpa_key_mic = bytes.fromhex(self.config.mic)
        ## 新的计算ptk方式
        amac = mac2str(self.config.mac_ap)
        smac = mac2str(self.config.mac_sta)

        # Compute PTK
        ptk = customPRF512(self.config.pmk, amac, smac, self.config.anonce, self.config.snonce)
        # logging.debug(f"ptk new : {ptk.hex()}")
        setattr(self, 'ptk', ptk)
        

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
        logging.info("-------------------------Key (Message 3 of 4): ")

        capt_eapol_p3 = AsyncSniffer(iface=self.config.iface,
                         lfilter=lambda r: (r.haslayer(EAPOL) 
                                            and r.getlayer(WPA_key).key_info  == self.eapkey_info['m3_keyinfo']
                                            ) ,
                         stop_filter=lambda r: (r.haslayer(EAPOL) 
                                            and r.getlayer(WPA_key).key_info  == self.eapkey_info['m3_keyinfo']
                                            ) ,
                         store=1, count=1,
                         timeout=self.timeout,
                         )
        # print(f"timeout : ", self.timeout)
        capt_eapol_p3.start()
        await asyncio.sleep(0.05)
        capt_eapol_p3.join()
        eapol_p3 = capt_eapol_p3.results
        
        if len(eapol_p3) > 0:
            logging.info("成功捕获到 EAPOl Message 3 of 4")
        else:
            logging.info("未成功捕获到符合条件的 EAPOL Message 3 of 4 ")
            sys.exit(1)
            
        eapol_3_packet = eapol_p3[-1]
        replay_counter = eapol_3_packet[WPA_key].replay_counter
        
        if self.config.wpa_keyver == 'WPA2':
            self.config.encrypt_msg = eapol_3_packet[WPA_key].wpa_key
            logging.debug(f"Encrypt Msg : {(self.config.encrypt_msg).hex()}")
            # print(f'{self.config.encrypt_msg.hex()}')

            ## 解密出 gtk
            tk = None
            gtk_decrypt = GTKDecrypt(self.config)
            gtk , tk = gtk_decrypt.get_gtk()
            logging.debug(f"GTK : {gtk}")
            logging.debug(f"TK : {tk}")
        elif self.config.wpa_keyver == 'WPA1':
            tk = self.ptk[32:48]  
            logging.debug(f"WPA1 TK : {tk}")
            
        # Key (Message 4 of 4)
        logging.info("-------------------------Key (Message 4 of 4): ")
        eapol_4 = EAPOL(version=1, type=3, len =95) / WPA_key(
                                                                descriptor_type=254,
                                                                key_info=self.eapkey_info['m4_keyinfo'],
                                                                len=32,
                                                                replay_counter = replay_counter # 和key 3 匹配, 用于匹配发送的每对消息。
                                                                )
        self.config.payload = bytes(eapol_4)
        calc_mic2 = Calc_MIC(wpa_keyver=self.config.wpa_keyver)
        pmk, ptk, MIC_m4 = calc_mic2.run(self.config)
        # logging.debug(self.config.payload.hex())
        # logging.debug(MIC_m4)
        eapol_4[WPA_key].wpa_key_mic = bytes.fromhex(MIC_m4)
        eapol_4_packet = Dot11(
            type=2,
            subtype=0,
            FCfield=1,
            addr1=self.config.mac_ap,
            addr2=self.config.mac_sta,
            addr3=self.config.mac_ap,
            SC=48)  / LLC() / SNAP() / eapol_4
        # eapol_4_packet.show()
        send(eapol_4_packet, iface = self.config.iface, verbose=0)

        if self.config.wpa_keyver == 'WPA1' and self.scene == Scene.wpa1_grouphandshake:
            # wpa1 group key handshake
            # 场景 WPA1 Group handshake
            logging.info("-------------------------Key (Group Message 1 of 2): ")
            group1_list = sniff(iface=self.config.iface,
                                lfilter=lambda r: (r.haslayer(Dot11TKIP) 
                                                and r[Dot11].addr1 == self.config.mac_sta 
                                                ) ,
                                count=1, store=1, 
                                timeout=self.timeout, 
                            #  prn = lambda x: logging.debug(x)
                                )
            if len(group1_list) > 0:
                logging.info("成功捕获到 Group Message 1 of 2 ")
            else:
                logging.error("未成功捕获到符合条件的 Group Message 1 of 2 ")
                sys.exit(1)
            
            ## decrypt group1
            group1 = group1_list[0]
            x = parse_data_pkt( group1[Dot11], tk)
            # LLC(x).show()
            
            # print(f"解密后 : {x.hex()}")
            replay_counter = LLC(x)[WPA_key].replay_counter
            gtk_cipher = LLC(x)[WPA_key].wpa_key
            
            ## decrypt gtk
            iv :bytes = LLC(x)[WPA_key].key_iv
            kek :bytes= self.config.ptk[16:32]
            key = iv + kek
            gtk_plain = ARC4_decrypt(key, gtk_cipher, skip=256)
            
            # logging.debug(f"gtk_cipher : {gtk_cipher.hex()}")
            logging.debug(f"GTK : {gtk_plain.hex()}")
            
            ## prepare group2
            logging.info("-------------------------Key (Group Message 2 of 2): ")
            
            group_1_eapol = EAPOL(
                                version="802.1X-2001", type="EAPOL-Key", len=95) \
                            / WPA_key(
                                descriptor_type=254,
                                # key_info=self.eapkey_info['m1_keyinfo'],
                                key_info=0x0311,
                                len=32,
                                replay_counter=replay_counter,
                                key_iv=bytes.fromhex("00000000000000000000000000000000"),
                                wpa_key_mic=bytes.fromhex("00000000000000000000000000000000"),
                                wpa_key_length=0,
                                )
            # 更新mic
            kck = self.config.ptk[:16]
            mic = hmac.new(kck, bytes(group_1_eapol), hashlib.md5).digest()[:16]
            logging.debug(f"group2 mic : {mic.hex()}")
            group_1_eapol[WPA_key].wpa_key_mic = mic
            # 从LLC到末尾都需要加密
            plain_str = (
            LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x888E)
            / group_1_eapol
            )
            
            mic_key_ap2sta = self.ptk[48:56]
            mic_key_sta2ap = self.ptk[56:64]
            data_to_enc = build_MIC_ICV(bytes(plain_str), mic_key_sta2ap, self.config.mac_sta, self.config.mac_ap )
            tkip_iv = 1 # 递增,步进1
            tkip_with_payload = build_TKIP_payload(bytes(data_to_enc), tkip_iv, self.config.mac_sta, tk)
            
            group_2 = (
            Dot11(
                type=2,
                subtype=0,
                FCfield="to-DS+protected",
                addr1=self.config.mac_ap,
                addr2=self.config.mac_sta,
                addr3=self.config.mac_ap,
                SC=4,) 
            / tkip_with_payload
            )

            ## send group2
            sendp(RadioTap() / group_2, iface=self.config.iface, verbose = 0)
            sys.exit(0)
        return tk
        # return 

# @pysnooper.snoop()
def test(
        iface = "monwlan2",
        ssid = "testnetwork",
        psk = "passphrase",
        ap_mac = "02:00:00:00:00:00",
        sta_mac = "02:00:00:00:01:00",
        scene = 3,
        wpa_keyver= 'WPA2',
        we_will_send = 'ARP',
        router_ip = '192.168.4.1',
        timeout = 3
):
    # @wrap_timeout(2)
    def create_test_with_timeout():
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
            timeout = timeout
        )
        
        # logging.debug(config.__dict__)

        if config.wpa_keyver == 'WPA1':
            vendor_info = TKIP_info.gen_tkip_info()
        else:
            vendor_info = RSN.get_rsn_info()
        conf.iface = config.iface       # scapy.config.conf.iface

        

        # 探测请求
        if scene == Scene.probeReq:
            logging.info(f'Start Probe request.')
            pr = ProbeReq.gen_Probe_req(ssid=config.ssid, dest_addr=config.mac_ap, source_addr=config.mac_sta)
            
            t1 = AsyncSniffer(iface=config.iface,
                                lfilter=lambda r: (r[Dot11].addr1 == config.mac_sta
                                                    and r.haslayer(Dot11ProbeResp) 
                                                    and r.getlayer(Dot11Elt).info  == config.ssid.encode()
                                                    ) ,
                                stop_filter=lambda r: (r[Dot11].addr1 == config.mac_sta
                                                    and r.haslayer(Dot11ProbeResp) 
                                                    and r.getlayer(Dot11Elt).info  == config.ssid.encode()
                                                    ) ,
                                # prn = lambda r: r.summary(),
                                store=1, 
                                #  count=1,    # when AsyncSniffer , don't count
                                timeout=timeout)
            t1.start()
            # time.sleep(0.06)
            sendp(pr, iface=config.iface, verbose=0)
            # time.sleep(0.06)
            # result = t1.stop()
            t1.join()
            result = t1.results
            
            if len(result) > 0:
                logging.info(f'Success recv Probe response.')
                if scene == Scene.probeReq:
                    sys.exit(0)
            else:
                logging.error(f'Not found Probe response.')
                sys.exit(1)
            
            
        monitor = Monitor(config.iface, config.mac_sta.lower(), config.mac_ap.lower(), timeout)
        connectionphase_1 = ConnectionPhase(monitor, config.mac_sta, config.mac_ap)
        
        # 链路认证
        logging.info("-------------------------Link Authentication Request : ")
        connectionphase_1.send_authentication()

        if connectionphase_1.state == "Authenticated":
            logging.info("STA is authenticated to the AP!")
        else:
            logging.info("STA is NOT authenticated to the AP!")
            sys.exit(1)
        # 场景 链路认证
        if scene == Scene.auth:
            sys.exit(0)

        # 链路关联
        logging.info("-------------------------Link Assocation Request : ")
        connectionphase_1.send_assoc_request(
            ssid=config.ssid, 
            vendor_info=vendor_info,
            )

        if connectionphase_1.state == "Associated":
            logging.info("STA is connected to the AP!")
        else:
            logging.info("STA is NOT connected to the AP!")
            sys.exit(1)
        # 场景 测试关联过程
        if scene == Scene.asso:
            sys.exit(0)

        connectionphase_2 = eapol_handshake(
            DUT_Object=config,
            vendor_info=vendor_info,
            scene=scene,
            timeout=timeout)
        TK = asyncio.run(connectionphase_2.run())
        logging.info("WiFi 协商完成!")
        
        # 场景 4-way handshake
        if scene == Scene.four_way_handshake:
            sys.exit(0)

        # # 和 AP 加密通信
        if wpa_keyver== 'WPA2':
            logging.info(f"\n-------------------------Send {we_will_send} Request : ")
            logging.info(f" TK : {TK}")
            setattr(config, 'TK', TK)
            
            encrypt_packet = ONCE_REQ.request_once(  config= config , req_type= we_will_send, router_ip=router_ip)
            
            sendp(RadioTap() / encrypt_packet, iface = config.iface, verbose=0)
            logging.info(f'We sent 1 {we_will_send} . ')
            
        # 场景 加密通信
        if scene == Scene.talktoap:
            sys.exit(0)
        
        
        # # 从 AP 离开
        deauth = Dot11(
                addr1=config.mac_ap,
                addr2=config.mac_sta,
                addr3=config.mac_ap,
                SC=16 * 5) / Dot11Deauth(reason=3)
        sendp(RadioTap() / deauth, iface = config.iface, verbose=0)
        logging.info(f'Leave from AP.')
            
        # 场景 deauth
        if scene == Scene.deauth:
            sys.exit(0)
        
    create_test_with_timeout()
    
if __name__ == "__main__":
    test()