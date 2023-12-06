import multiprocessing
from scapy.all import *

from utils.bridge import *
class Dot11EltRates(Packet):
    """
    Our own definition for the supported rates field
    """
    name = "802.11 Rates Information Element"
    # Our Test AP has the rates 6, 9, 12 (B), 18, 24, 36, 48 and 54, with 12
    # Mbps as the basic rate - which does not have to concern us.
    supported_rates = [0x82, 0x84, 0x8b, 0x96, 0x12, 0x24, 0x48, 0x6c]
 
    fields_desc = [
        ByteField("ID", 1),
        ByteField("len", len(supported_rates))
        ]
 
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(
            index + 1), rate))
        
class RSN():
    def get_rsn_info(self):
        rsn_info = Dot11EltRSN(
                len=22,         # len=22  smyl    /      len=20   xiaomi hotspot
                group_cipher_suite=RSNCipherSuite(),
                nb_pairwise_cipher_suites=1,
                pairwise_cipher_suites=[RSNCipherSuite()],
                nb_akm_suites=1,
                akm_suites=[AKMSuite(suite=2)], # 重要, =2 代表 psk
                mfp_capable=0,                  # 管理帧保护, =1 or =0, 受保护的管理帧强制对断开连接帧进行加密
                mfp_required=0 ,
                gtksa_replay_counter=0 ,      
                ptksa_replay_counter=0
                )
        
        return rsn_info
 
class Monitor:
    def __init__(self, mon_ifc, sta_mac, bssid):
        """
 
        :param mon_ifc: WLAN interface to use as a monitor
        :param channel: Channel to operate on
        :param sta_mac: MAC address of the STA
        :param bssid: BSSID of the AP to attack
        """
        self.mon_ifc = mon_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
        self.auth_found = False
        self.assoc_found = False
        self.eapol_1 = False
        self.eapol_3_found = False
        self.dot11_rates = Dot11EltRates()
        
    # def ack(self, dest_mac):
    #     dot11 = Dot11(type=1, subtype=13, addr1=dest_mac)
    #     frame = dot11 / Raw(b"123456")
    #     return frame
 
    def send_packet(self, packet, packet_type=None):
        """
        Send and display a packet.
 
        :param packet_type: Specific types require
        :param packet:
        :return:
        """
        # Send out the packet
        logging.info(f"Send package packet_type: {packet_type}")
        if packet_type is None:
            send(packet)

        elif packet_type == "AssoReq":
            packet /= self.dot11_rates
            send(packet)
        else:
            logging.info("Packet Type '{0}' unknown".format(packet_type))
 
    def check_auth(self, packet):
        """
        Try to find the Authentication from the AP
 
        :param packet: sniffed packet to check for matching authentication
        """
        # print("SELF : ",self.bssid,self.bssid,self.sta_mac)
        # print("Packet : ",packet[Dot11].addr1,packet[Dot11].addr2,packet[Dot11].addr3)
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
 
        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.auth_found = True
            logging.info("Detected Authentication from Source {0}".format(
                seen_bssid))
        return self.auth_found
 
    def check_assoc(self, packet):
        """
        Try to find the Association Response from the AP
 
        :param packet: sniffed packet to check for matching association
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
 
        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.assoc_found = True
            logging.debug("Detected Association Response from Source {0}".format(
                seen_bssid))
        return self.assoc_found
 
    def search_auth(self, mp_queue):
        logging.info("Scanning max 1 seconds for Authentication "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11Auth),
              stop_filter=self.check_auth, timeout=1, prn = lambda x: logging.debug(x))
        mp_queue.put(self.auth_found)
 
    def search_assoc_resp(self, mp_queue):
        logging.info("Scanning max 1 seconds for Association Response "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11AssoResp),
              stop_filter=self.check_assoc, timeout=1, prn = lambda x: logging.debug(x))
        mp_queue.put(self.assoc_found)
        
    
        
