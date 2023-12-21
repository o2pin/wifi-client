import logging
import os
import random
import re
import subprocess
import time
from utils.bridge import *

from .dot11 import Dot11, Dot11Elt, Dot11EltDSSSet, Dot11EltHTCapabilities, Dot11EltRates, Dot11EltVendorSpecific, Dot11ProbeReq, Dot11ProbeResp, RadioTap

from .libwifi import ETHER_BROADCAST, set_channel
from .dot11p2p import ChannelEntry, ChannelListAttribute, ConfigurationTimeoutAttribute, DeviceName, Dot11EltWiFiAllianceP2P, GONegotiatioRequest, GONegotiationConfirmation, GONegotiationResponse, GroupOwnerIntentAttribute, IntendedP2PInterfaceAddressAttribute, ListenChannelAttribute, OperatingChannelAttribute, P2PAttribute, P2PCapabilityAttribute, P2PDeviceInfoAttribute, P2PGroupIDAttribute, P2PProvisionDiscoveryRequest, PrimaryDeviceTypeData, StatusAttribute
from .dot11wps import AssociationStateAttribute, ConfigurationErrorAttribute, ConfigurationMethodsAttribute, DeviceNameAttribute, DevicePasswordIDAttribute, Dot11EltWPS, ManufacturerAttribute, ModelNameAttribute, ModelNumberAttribute, PrimaryDeviceTypeAttribute, RFBandsAttribute, RequestTypeAttribute, ResponseTypeAttribute, SerialNumberAttribute, UUIDEAttribute, VersionAttribute, WiFiSimpleConfigurationStateAttribute, WPSAttribute

def get_iface_mac(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("addr ([\w:]+)")
	return str(p.search(output).group(1))

def build_p2p_probe_request(iface, channel=1, sn=0, dst=ETHER_BROADCAST, listen_channel=11):
    dot11 = Dot11(type=0, subtype=4, addr1=dst, addr2=get_iface_mac(iface), addr3=ETHER_BROADCAST, SC=sn*16)
    elt_rates = Dot11EltRates(rates=[0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c])
    pkt = dot11 / Dot11ProbeReq() / Dot11Elt(ID=0, info="{}".format("DIRECT-")) / elt_rates
    pkt /= Dot11EltDSSSet(ID=3,channel=channel)
    pkt /= Dot11EltHTCapabilities(Max_A_MSDU=1, Rx_STBC=1,Tx_STBC=1,Short_GI_40Mhz=1,Short_GI_20Mhz=1,
                                  SM_Power_Save=0x3,Supported_Channel_Width=1,Min_MPDCU_Start_Spacing=0x5,Max_A_MPDU_Length_Exponent=0x3,
                                  RX_MSC_Bitmask=0xF0,Compressed_Steering_n_Beamformer_Antennas_Supported=0x2)


    pkt /= Dot11EltWPS(len=103)
    pkt /= VersionAttribute(id=0x104a, Version=0x10)
    pkt /= RequestTypeAttribute(id=0x103A, RequestType=0x01)
    pkt /= ConfigurationMethodsAttribute(id=0x1008, ConfigurationMethods=0x4388)
    pkt /= UUIDEAttribute(id=0x1047, UUIDE=0x449264cd843b5380bc3227dd58793d63)
    pkt /= PrimaryDeviceTypeAttribute(id=0x1054)
    pkt /= RFBandsAttribute(id=0x103c, RFBands=0x03)
    pkt /= AssociationStateAttribute(id=0x1002)
    pkt /= ConfigurationErrorAttribute(id=0x1009)
    pkt /= DevicePasswordIDAttribute(id=0x1012)
    pkt /= ManufacturerAttribute(id=0x1021, Manufacturer=0x20)
    pkt /= ModelNameAttribute(id=0x1023, ModelName=0x20)
    pkt /= ModelNumberAttribute(id=0x1024, ModelNumber=0x20)
    pkt /= DeviceNameAttribute(id=0x1011, DeviceName="wfuzz-p2p")

    pkt /= Dot11EltWiFiAllianceP2P(len=17)
    pkt /= P2PCapabilityAttribute(id=2, DeviceCapability=0x25)
    pkt /= ListenChannelAttribute(id=6, OperatingClass=0x51, ChannelNumber=listen_channel)

    pkt.build()
    return pkt

def build_p2p_probe_response(dst, iface, channel=1, sn=0):

    iface_addr=get_iface_mac(iface)

    dot11 = Dot11(type=0, subtype=5, ID=0x3c00,
                  addr1=dst, addr2=iface_addr,
                  addr3=iface_addr, SC=sn*16)
    elt_rates = Dot11EltRates(rates=[0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c])

    time_stamp = int(time.process_time_ns() * 0.001)
    pkt = dot11 / Dot11ProbeResp(timestamp=time_stamp, cap=0x3004) / Dot11Elt(ID=0, info="{}".format("DIRECT-")) / elt_rates
    pkt /= Dot11EltDSSSet(ID=3,channel=channel)

    pkt /= Dot11EltWPS(len=90)
    pkt /= VersionAttribute(id=0x104a, Version=0x10)
    pkt /= WiFiSimpleConfigurationStateAttribute(id=0x1044,State=0x01)
    pkt /= ResponseTypeAttribute(id=0x103B,ResponseType=0x00)
    pkt /= UUIDEAttribute(id=0x1047, UUIDE=0x449264cd843b5380bc3227dd58793d63)
    pkt /= ManufacturerAttribute(id=0x1021, Manufacturer=0x20)
    pkt /= ModelNameAttribute(id=0x1023, ModelName=0x20)
    pkt /= ModelNumberAttribute(id=0x1024, ModelNumber=0x20)
    pkt /= SerialNumberAttribute(id=0x1042, SerialNumber=0x20)
    pkt /= PrimaryDeviceTypeAttribute(id=0x1054)
    pkt /= DeviceNameAttribute(id=0x1011, DeviceName="wfuzz-p2p")
    pkt /= ConfigurationMethodsAttribute(id=0x1008, ConfigurationMethods=0x4388)

    pkt /= Dot11EltWiFiAllianceP2P(len=42)
    pkt /= P2PCapabilityAttribute(id=2, DeviceCapability=0x25)

    pkt /= P2PDeviceInfoAttribute(id=13, len=30, P2PDeviceAddress=iface_addr,
                                  ConfigMethods=0x1108, DeviceName=DeviceName(AttributeType=0x1011, data="wfuzz-p2p"))
    return pkt

def build_go_negotiation_request(iface, sn=0, dst=ETHER_BROADCAST, listen_channel=11, seed=1):
    iface_addr=get_iface_mac(iface)

    dot11 = Dot11(type=0, subtype=13, addr1=dst, addr2=iface_addr, addr3=ETHER_BROADCAST, SC=sn*16)
    pkt = dot11 / GONegotiatioRequest()
    pkt /= Dot11EltWiFiAllianceP2P(len=97, P2PAttributes=[
        P2PCapabilityAttribute(id=2, DeviceCapability=0x25, GroupCapability=0x2a),
        GroupOwnerIntentAttribute(Intent=seed % 16, Tiebreaker = seed % 2),
        ConfigurationTimeoutAttribute(GOConfigurationTimeout=100, ClientConfigurationTimeout=20),
        ListenChannelAttribute(id=6, OperatingClass=0x51, ChannelNumber=listen_channel),
        IntendedP2PInterfaceAddressAttribute(P2PInterfaceAddress=iface_addr),
        ChannelListAttribute(len=18,ChannelEntryList=[
            ChannelEntry(OperatingClass=81,number=13,Channel_List=[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d]),
        ]),
        P2PDeviceInfoAttribute(id=13, len=30, P2PDeviceAddress=iface_addr, ConfigMethods=0x0188,
                                  PrimaryDeviceType=PrimaryDeviceTypeData(CategoryID=10,OUI=0x0050f204, SubCategoryID=5),
                                  DeviceName=DeviceName(AttributeType=0x1011, length=9, data="wfuzz-p2p")),
        OperatingChannelAttribute(OperatingClass=115, ChannelNumber=1)
    ])

    pkt /= Dot11EltWPS(len=15, WPSAttributes=[
        VersionAttribute(Version=0x10),
        DevicePasswordIDAttribute(DevicePasswordID=0x0004),
        ])
    pkt.build()
    return pkt

def build_go_negotiation_response(iface, sn=0, dst=ETHER_BROADCAST, listen_channel=11, seed=1):
    iface_addr=get_iface_mac(iface)

    dot11 = Dot11(type=0, subtype=13, ID=0x2800,
                  addr1=dst, addr2=iface_addr,
                  addr3=iface_addr, SC=sn*16)
    pkt = dot11 / GONegotiationResponse()
    pkt /= Dot11EltWiFiAllianceP2P(len=173, P2PAttributes=[
        StatusAttribute(StatusCode=0),
        P2PCapabilityAttribute(id=2, DeviceCapability=0x25, GroupCapability=0x2a),
        GroupOwnerIntentAttribute(Intent=seed % 16, Tiebreaker = seed % 2),
        ConfigurationTimeoutAttribute(GOConfigurationTimeout=100, ClientConfigurationTimeout=20),
        OperatingChannelAttribute(OperatingClass=115, ChannelNumber=48),
        IntendedP2PInterfaceAddressAttribute(P2PInterfaceAddress=iface_addr),
        ChannelListAttribute(len=18,ChannelEntryList=[
            ChannelEntry(OperatingClass=81,number=13,Channel_List=[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d]),
        ]),
        P2PDeviceInfoAttribute(id=13, len=30, P2PDeviceAddress=iface_addr, ConfigMethods=0x0188,
                                  PrimaryDeviceType=PrimaryDeviceTypeData(CategoryID=10,OUI=0x0050f204, SubCategoryID=5),
                                  DeviceName=DeviceName(AttributeType=0x1011, length=9, data="wfuzz-p2p")),
        P2PGroupIDAttribute(len=21, P2P_device_address=iface_addr, SSIDElement="DIRECT-wingfuzz")
    ])
    pkt /= Dot11EltWPS(len=15, WPSAttributes=[
        VersionAttribute(Version=0x10),
        DevicePasswordIDAttribute(DevicePasswordID=0x0004),
        ])

    pkt.build()
    return pkt


def build_go_negotiation_confirmation(iface, sn=0, dst=ETHER_BROADCAST):
    iface_addr=get_iface_mac(iface)

    dot11 = Dot11(type=0, subtype=13, ID=0x2800,
                  addr1=dst, addr2=iface_addr,
                  addr3=dst, SC=sn*16)
    pkt = dot11 / GONegotiationConfirmation()
    pkt /= Dot11EltWiFiAllianceP2P(len=66, P2PAttributes=[
        StatusAttribute(StatusCode=0),
        P2PCapabilityAttribute(id=2, DeviceCapability=0x25, GroupCapability=0x2a),
        OperatingChannelAttribute(OperatingClass=81, ChannelNumber=1),
        ChannelListAttribute(len=18,ChannelEntryList=[
            ChannelEntry(OperatingClass=81,number=13,Channel_List=[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d])
        ]),
        P2PGroupIDAttribute(len=21, P2P_device_address=iface_addr, SSIDElement="DIRECT-wingfuzz")
    ])
    pkt.build()
    return pkt

def build_p2p_provision_discovery_request(iface, sn=0, dst=ETHER_BROADCAST):
    iface_addr=get_iface_mac(iface)

    dot11 = Dot11(type=0, subtype=13, ID=0x2800,
                  addr1=dst, addr2=iface_addr,
                  addr3=dst, SC=sn*16)
    pkt = dot11 / P2PProvisionDiscoveryRequest()
    pkt /= Dot11EltWiFiAllianceP2P(len=42, P2PAttributes=[
        P2PCapabilityAttribute(id=2, DeviceCapability=0x25, GroupCapability=0x2a),
        P2PDeviceInfoAttribute(id=13, len=30, P2PDeviceAddress=iface_addr, ConfigMethods=0x0188,
                                  PrimaryDeviceType=PrimaryDeviceTypeData(CategoryID=10,OUI=0x0050f204, SubCategoryID=5),
                                  DeviceName=DeviceName(AttributeType=0x1011, length=9, data="wfuzz-p2p"))
    ])
    pkt /= Dot11EltWPS(len=10, WPSAttributes=[
            ConfigurationMethodsAttribute(id=0x1008, ConfigurationMethods=0x2288)
        ])
    pkt.build()
    return pkt

SequenceNumber = 0

def make_check_p2p_req(addr):
    dst = addr
    def check_p2p_req(pkt):
        pkt.build()
        if dst == "ff:ff:ff:ff:ff:ff":
            return pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11EltWiFiAllianceP2P)
        else:
            return pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11EltWiFiAllianceP2P) and pkt.addr2 == dst
    return check_p2p_req

def make_check_p2p_resp(addr):
    dst = addr
    def check_p2p_resp(pkt):
        pkt.build()
        if dst == "ff:ff:ff:ff:ff:ff":
            return pkt.haslayer(Dot11ProbeResp) and pkt.haslayer(Dot11EltWiFiAllianceP2P)
        else:
            return pkt.haslayer(Dot11ProbeResp) and pkt.haslayer(Dot11EltWiFiAllianceP2P) and pkt.addr2 == dst
    return check_p2p_resp

def make_check_p2p_go_negotiation_response(addr):
    dst = addr
    def check_p2p_go_negotiation_resp(pkt):
        if dst == "ff:ff:ff:ff:ff:ff":
            return pkt.haslayer(GONegotiationResponse) and pkt.haslayer(Dot11EltWiFiAllianceP2P)
        else:
            return pkt.haslayer(GONegotiationResponse) and pkt.haslayer(Dot11EltWiFiAllianceP2P) and pkt.addr2 == dst
    return check_p2p_go_negotiation_resp

def make_check_p2p_go_negotiation_request(addr):
    dst = addr
    def check_p2p_go_negotiation_req(pkt):
        if dst == "ff:ff:ff:ff:ff:ff":
            return pkt.haslayer(GONegotiatioRequest) and pkt.haslayer(Dot11EltWiFiAllianceP2P)
        else:
            return pkt.haslayer(GONegotiatioRequest) and pkt.haslayer(Dot11EltWiFiAllianceP2P) and pkt.addr2 == dst
    return check_p2p_go_negotiation_req

def make_process_p2p_req(iface="wlan0mon",listen_channel=11,SequenceNumber=1):
    iface = iface
    listen_channel=listen_channel
    sequence_number=SequenceNumber
    def process_p2p_req(pkt):
        logging.info("recv p2p req")
        pkt.build()
        resp = build_p2p_probe_response(dst=pkt.addr2, iface=iface, channel=listen_channel, sn=sequence_number)
        send(resp , iface=iface)
        logging.info("send p2p response")
    return process_p2p_req

def make_process_p2p_resp(iface="wlan0mon",listen_channel=11):
    iface = iface
    listen_channel=listen_channel
    def process_p2p_resp(pkt):
        logging.info("recv p2p response: ", listen_channel)
    return process_p2p_resp

def make_process_p2p_go_negotiation_response(iface="wlan0mon"):
    iface = iface
    def process_p2p_go_negotiation_response(pkt):
        logging.info("P2P process p2p go negotiation response")
        global SequenceNumber
        confirmation = build_go_negotiation_confirmation(dst=pkt.addr2, sn=SequenceNumber, iface=iface)
        SequenceNumber+=1
        send(confirmation , iface=iface)
        logging.info("send go negotiation confirmation")
    return process_p2p_go_negotiation_response

def make_process_p2p_go_negotiation_request(iface="wlan0mon"):
    iface = iface
    def process_p2p_go_negotiation_request(pkt):
        global SequenceNumber
        confirmation = build_go_negotiation_response(dst=pkt.addr2, sn=SequenceNumber, iface=iface)
        SequenceNumber+=1
        send(confirmation , iface=iface)
    return process_p2p_go_negotiation_request

def DeviceDiscoveryTest(
          iface = "wlan0mon",
          dst = "ff:ff:ff:ff:ff:ff",
          listen_channel = 6,
          scene=0,
          timeout = 0.1024,
          seed=0
):
    conf.iface = iface
    logging.info("P2P Device Discovery Test")
    logging.info("iface : {}".format(iface))
    logging.info("dst : {}".format(dst))
    logging.info("timeout : {}s".format(timeout))
    global SequenceNumber
    if seed != 0:
        SequenceNumber = seed % 4095
    else:
        SequenceNumber = random.randint(1,4095)
    if scene == 0:
        logging.info("P2P search")

        pkt = build_p2p_probe_request(iface, channel=1, sn=SequenceNumber, dst=dst, listen_channel=listen_channel)
        set_channel(iface, 1)
        send(pkt , iface=iface)
        SequenceNumber += 1

        pkt = build_p2p_probe_request(iface, channel=6, sn=SequenceNumber, dst=dst, listen_channel=listen_channel)
        set_channel(iface, 6)
        send(pkt , iface=iface)
        SequenceNumber += 1

        pkt = build_p2p_probe_request(iface, channel=11, sn=SequenceNumber, dst=dst, listen_channel=listen_channel)
        set_channel(iface, 11)
        send(pkt , iface=iface)
        exit(0)


    elif scene == 1:
        logging.info("P2P listen")
        set_channel(iface, listen_channel)
        lst = sniff(iface=iface,
                lfilter=make_check_p2p_req(dst),
                prn=make_process_p2p_req(iface, listen_channel,SequenceNumber=SequenceNumber),
                timeout=timeout,
                count=1
        )
        if len(lst) == 0:
            exit(1)
        else:
            exit(0)


def GroupFormationTest(
          iface = "wlan0mon",
          dst = "ff:ff:ff:ff:ff:ff",
          listen_channel = 6,
          scene=0,
          timeout = 0.1024,
          seed=0
):
    conf.iface = iface
    logging.info("P2P Group Formation Test")
    logging.info("iface : {}".format(iface))
    logging.info("dst : {}".format(dst))
    logging.info("timeout : {}s".format(timeout))
    global SequenceNumber
    if seed == 0:
        seed = random.randint(1,65535)
    SequenceNumber = seed % 4095
    if scene==0:
        logging.info("scene 0: GO Negotiation")
        pkt = build_go_negotiation_request(iface, sn=SequenceNumber, dst=dst, listen_channel=listen_channel, seed=seed)
        SequenceNumber += 1
        send(pkt , iface=iface)
        lst = sniff(iface=iface,
            lfilter=make_check_p2p_go_negotiation_response(dst),
            prn=make_process_p2p_go_negotiation_response(iface),
            timeout=timeout,
        )
    elif scene==1:
        logging.info("scene 1: Provision Discovery")
        pkt = build_p2p_provision_discovery_request(iface, sn=SequenceNumber, dst=dst)
        SequenceNumber += 1
        send(pkt , iface=iface)