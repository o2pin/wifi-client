import multiprocessing
from scapy.all import *
from pbkdf2 import PBKDF2
import binascii
import hashlib, hmac, sys, struct
 
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
        if packet_type is None:
            send(packet)
        elif packet_type == "AssoReq":
            packet /= self.dot11_rates
            send(packet)
        else:
            print("Packet Type '{0}' unknown".format(packet_type))
 
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
            print("Detected Authentication from Source {0}".format(
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
            print("Detected Association Response from Source {0}".format(
                seen_bssid))
        return self.assoc_found
 
    def search_auth(self, mp_queue):
        print("\nScanning max 1 seconds for Authentication "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11Auth),
              stop_filter=self.check_auth,
              timeout=1)
        mp_queue.put(self.auth_found)
 
    def search_assoc_resp(self, mp_queue):
        print("\nScanning max 1 seconds for Association Response "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11AssoResp),
              stop_filter=self.check_assoc,
              timeout=1)
        mp_queue.put(self.assoc_found)
        
        
class Calc_MIC():
    
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

    def calc_ptk(self, pmk, anonce, snonce, mac_ap, mac_client):
        key_data = min(mac_ap, mac_client) + max(mac_ap, mac_client) + min(anonce,snonce) + max(anonce,snonce)
        # ptk = customPRF512(pmk, pke, key_data)
        macs = self.min_max(mac_ap, mac_client)
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


    def run(self, WiFi_Object):
        config = WiFi_Object
        mac_ap = bytes.fromhex((config.mac_ap).replace(":",""))
        mac_client = bytes.fromhex((config.mac_client).replace(":",""))
        # print("-------------------------\n", mac_ap,mac_client, config.anonce, config.snonce)
        # eapol_1
        pmk = self.calculate_WPA_PMK(config.psk, config.ssid)
        ptk = self.calc_ptk(pmk, config.anonce, config.snonce, mac_ap, mac_client)
        MIC = self.calculate_WPA_MIC(ptk, config.payload)
        # eapol_3
        # m4_mic = "28bffa440f189c2dfe06f2e3486f3b83"
        # m4_payload = bytes.fromhex("010300970213ca00100000000000000002777f196229c576fda543ca0c5d3c96ac23bc4c67f6e8ea618966dbc7e0150654000000000000000000000000000000008392ba0000000000000000000000000000000000000000000000000000000000003804439acbbfc551b36a900fc19eef6655f6f371c7a7e54c11a3738aef32fdf42de0cd00ac6a91360fbac7efec0f745d1f6c38f4b665642542")
        # MIC_2 = self.calculate_WPA_MIC(ptk, m4_payload)
        # print("MIC_2 : " + MIC_2)
                
        return MIC
