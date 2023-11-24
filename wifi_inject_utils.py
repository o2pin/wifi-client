import multiprocessing
from scapy.all import *
import binascii
import hashlib, hmac, sys, struct
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
 
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
        # tk = ptk[64:96]
        # mic_tx = ptk[96:112]
        # mic_rx = ptk[112:]
        
        return ptk,  kek
    
    def get_gtk(self):
        
        ptk , kek = self.generate_ptk_kek()
        kek = bytes.fromhex(kek)
        encrypt_msg = self.config.encrypt_msg
        print("生成gtk: ", kek, encrypt_msg)
        gtk = aes_key_unwrap(kek, encrypt_msg).hex()[60:-4]
        
        return gtk
    
    