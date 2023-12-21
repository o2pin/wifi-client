import struct
from scapy.packet import Packet
from scapy.fields import BitField, ByteEnumField, ByteField, ConditionalField, FieldLenField, FieldListField, FlagsField, IntField, MACField, NBytesField, OUIField, PacketField, PacketListField, ShortEnumField, StrFixedLenField, StrLenField, XByteField, ShortField, XIntField, XShortField
from scapy.fields import LEShortField

from scapy.compat import orb
from .dot11 import _Dot11EltUtils, _Dot11MacField, Dot11, Dot11Elt, _dot11_id_enum, Dot11EltVendorSpecific

from scapy.packet import bind_layers

p2p_attribute_id_definitions = {
    0: "Status",
    1: "Minor Reason Code",
    2: "P2P Capability",
    3: "P2P Device ID",
    4: "Group Owner Intent",
    5: "Configuration Timeout",
    6: "Listen Channel",
    7: "P2P Group BSSID",
    8: "Extended Listen Timing",
    9: "Intended P2P Interface Address",
    10: "P2P Manageability",
    11: "Channel List",
    12: "Notice of Absence",
    13: "P2P Device Info",
    14: "P2P Group Info",
    15: "P2P Group ID",
    16: "P2P Interface",
    17: "Operating Channel",
    18: "Invitation Flags",
    19: "Out-of-Band Group Owner Negotiation Channel",
    20: "Unused",
    21: "Service Hash",
    22: "Session Information Data Info",
    23: "Connection Capability Info",
    24: "Advertisement_ID Info",
    25: "Advertised Service Info",
    26: "Session ID Info",
    27: "Feature Capability",
    28: "Persistent Group Info",
    221: "Vendor specific attribute",
}

status_code_definitions = {
    0: "Success",
    1: "Fail; information is currently unavailable.",
    2: "Fail; incompatible parameters.",
    3: "Fail; limit reached.",
    4: "Fail; invalid parameters.",
    5: "Fail; unable to accommodate request.",
    6: "Fail; previous protocol error, or disruptive behavior.",
    7: "Fail; no common channels.",
    8: "Fail; unknown P2P Group.",
    9: "Fail: both P2P Devices indicated an Intent of 15 in Group Owner Negotiation.",
    10: "Fail; incompatible provisioning method.",
    11: "Fail: rejected by user.",
    12: "Success: Accepted by user"
}

minor_reason_code_definitions = {
    1: "Disassociated/deauthenticated from the WLAN AP because the Cross Connection capability bit is 1 and this capability within this device is outside the IT defined policy. ",
    2: "Disassociated/deauthenticated from the WLAN AP because the P2P Infrastructure Managed bit is 0.",
    3: '''Disassociated/deauthenticated from the WLAN because a P2P Concurrent Device is not setting P2P Coexistence Parameters
within the IT defined policy; this applies to either primary or secondary P2P Coexistence Parameters.''',
    4: '''Disassociated/deauthenticated from the WLAN AP because the
P2P Device has included the P2P IE with the P2P Infrastructure
Managed bit set to 1 and P2P operation within this device is
outside the IT defined policy.'''
}

configuration_methods = {
    0x0001: "USBA (Flash Drive)",
    0x0002: "Ethernet",
    0x0004: "Label",
    0x0008: "Display",
    0x0010: "External NFC Token",
    0x0020: "Integrated NFC Token",
    0x0040: "NFC Interface",
    0x0080: "Pushbutton",
    0x0100: "Keypad",
    0x0280: "Virtual Pushbutton",
    0x0480: "Physical Pushbutton",
    0x0880: "(Reserved)",
    0x1000: "P2Ps Default Configuration Method",
    0x2008: "Virtual Display PIN",
    0x4008: "Physical Display PIN"
}

role_indication = {
    0x00: "the P2P device is not in a group",
    0x01: "the P2P device is a Group Client",
    0x02: "the P2P device is a Group Owner"
}

connection_capabilities = {
    0x01: "New",
    0x02: "Cli",
    0x04: "GO",
    0x05: "New, GO",
    0x06: "Cli, GO"
}

p2p_public_action_frame_type = {
    0: "GO Negotiation Request",
    1: "GO Negotiation Response",
    2: "GO Negotiation Confirmation",
    3: "P2P Invitation Request",
    4: "P2P Invitation Response",
    5: "Device Discoverability Request",
    6: "Device Discoverability Response",
    7: "Provision Discovery Request",
    8: "Provision Discovery Response"
}

device_capability_bitmap = [
    "Service Discovery",
    "P2P Client Discoverability",
    "Concurrent Operation",
    "P2P Infrastructure Managed",
    "P2P Device Limit",
    "P2P Invitation Procedure",
    "Reserved",
    "Reserved"
]

group_capability_bitmap = [
    "P2P Group Owner",
    "Persistent P2P Group",
    "P2P Group Limit",
    "Intra-BSS Distribution",
    "Cross Connection",
    "Persistent Reconnect",
    "Group Formation",
    "IP Address Allocation"
]

manageability_bitmap = [
    "P2P Device Management",
    "Cross Connection Permitted",
    "Coexistence Optional"
]

class ChannelEntry(Packet):
    name = "Channel Entry"
    show_indent = 0
    fields_desc = [
        ByteField("OperatingClass", 0),
        FieldLenField("number", None, fmt="B", count_of="Channel_List"),
        FieldListField("Channel_List", [], XByteField("", 0), count_from = lambda pkt: pkt.number)
    ]

class NoticeOfAbsenceDescriptor(Packet):
    name = "Notice of Absence Descriptor"
    fields_desc = [
        ByteField("CountOrType", 0),
        XIntField("Duration", 0),
        XIntField("Interval", 0),
        XIntField("StartTime", 0)
    ]

class PrimaryDeviceTypeData(Packet):
    name = "Primary Device Type"
    fields_desc = [
        # XShortField("Attribute ID", 0),
        # ShortField("Length", 0),
        XShortField("CategoryID", 0),
        XIntField("OUI", 0),
        XShortField("SubCategoryID", 0),
    ]

    def extract_padding(self, s):
        return "", s

class TLVDataFormat(Packet):
    name = "TLV Data Format"
    fields_desc = [
        XShortField("AttributeType", 0),
        FieldLenField("length", None, fmt="H", length_of="data"),
        StrLenField("data", "", length_from=lambda pkt:pkt.length)
    ]

    def extract_padding(self, s):
        return "", s

class SecondaryDeviceTypeData(PrimaryDeviceTypeData):
    name = "Secondary Device Type"

class DeviceName(TLVDataFormat):
    AttributeType=0x1011
    name = "Device Name"

class AdvertisedServiceDescriptor(Packet):
    name = "Advertised Service Descriptor"
    fields_desc = [
        XIntField("AdvertisementID", 0),
        ShortEnumField("ConfigMethods", 0x1000, configuration_methods),
        FieldLenField("len", None, count_of="Name"),
        StrLenField("Name", "", length_from=lambda pkt:pkt.len)
    ]


class P2PClientInfoDescriptor(Packet):
    name = "P2P Client Info Descriptor"
    fields_desc = [
        ByteField("len", 0),
        NBytesField("P2PDeviceAddress", 0, 6),
        NBytesField("P2PInterfaceAddress", 0, 6),
        FlagsField("DeviceCapability", 0, 8, device_capability_bitmap),
        ShortEnumField("ConfigMethods", 0x1000, configuration_methods),
        PacketField("PrimaryDeviceType", None, PrimaryDeviceTypeData),
        ByteField("number_of_secondary_device_types", 0),
        PacketListField("SecondaryDeviceTypeList", [], SecondaryDeviceTypeData,
                        count_from = lambda pkt: pkt.number_of_secondary_device_types),
        PacketField("DeviceName", None, DeviceName)
    ]

#8.4.2.2 of IEEE 802.11-2012
class SSIDElement(Packet):
    name = "SSID element"
    fields_desc = [
        ByteField("ElementID", 0),
        FieldLenField("len", None, length_of="SSID"),
        StrLenField("SSID", "", length_from=lambda pkt:pkt.len)
    ]

class P2PAttribute(Packet):
    name = "P2P Attribute"
    match_subclass = True
    show_indent = 0
    fields_desc = [
        ByteEnumField("id", 0, p2p_attribute_id_definitions),
        LEShortField("len", None),
        StrLenField("body", "", length_from=lambda x: x.len)
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            id = _pkt[0]
            if id == 0:
                return StatusAttribute
            if id == 1:
                return MinorReasonCodeAttribute
            if id == 2:
                return P2PCapabilityAttribute
            if id == 3:
                return P2PDeviceIDAttribute
            if id == 4:
                return GroupOwnerIntentAttribute
            if id == 5:
                return ConfigurationTimeoutAttribute
            if id == 6:
                return ListenChannelAttribute
            if id == 7:
                return P2PGroupBSSIDAttribute
            if id == 8:
                return ExtendedListenTimingAttribute
            if id == 9:
                return IntendedP2PInterfaceAddressAttribute
            if id == 10:
                return P2PManageabilityAttribute
            if id == 11:
                return ChannelListAttribute
            if id == 12:
                return NoticeOfAbsenceAttribute
            if id == 13:
                return P2PDeviceInfoAttribute
            if id == 14:
                return P2PGroupInfoAttribute
            if id == 15:
                return P2PGroupIDAttribute
            if id == 16:
                return P2PInterfaceAttribute
            if id == 17:
                return OperatingChannelAttribute
            if id == 18:
                return InvitationFlagsAttribute
            if id == 19:
                return OutOfBandGroupOwnerNegotiationChannelAttribute
            if id == 21:
                return ServiceHashAttribute
            if id == 22:
                return SessionInformationDataInfo
            if id == 23:
                return ConnectionCapabilityInfoAttribute
            if id == 24:
                return AdvertisementIDInfoAttribute
            if id == 25:
                return AdvertisedServiceInfoAttribute
            if id == 26:
                return SessionIDInfoAttribute
            if id == 27:
                return FeatureCapabilityInfoAttribute
            if id == 28:
                return PersistentGroupInfoAttribute
            return cls
        return cls

class StatusAttribute(P2PAttribute):
        name = "Status Attribute"
        match_subclass = True
        id = 0
        len = 1
        fields_desc = P2PAttribute.fields_desc[:2] + [
            ByteEnumField("StatusCode", 0, status_code_definitions)
        ]

class MinorReasonCodeAttribute(P2PAttribute):
        name = "Minor Reason Code Attribute"
        match_subclass = True
        id = 1
        len = 1
        fields_desc = P2PAttribute.fields_desc[:2] + [
            ByteEnumField("MinorReasonCode", 1, minor_reason_code_definitions)
        ]

class P2PCapabilityAttribute(P2PAttribute):
        name = "P2P Capability Attribute"
        match_subclass = True
        id = 2
        len = 2
        fields_desc = P2PAttribute.fields_desc[:2] + [
            FlagsField("DeviceCapability", 0, 8, device_capability_bitmap),
            FlagsField("GroupCapability", 0, 8, group_capability_bitmap)
        ]

class P2PDeviceIDAttribute(P2PAttribute):
        name = "P2P Device ID Attribute"
        match_subclass = True
        id = 3
        len = 6
        fields_desc = P2PAttribute.fields_desc[:2] + [
            NBytesField("DeviceAddress", 0, 6)
        ]

class GroupOwnerIntentAttribute(P2PAttribute):
        name = "Group Owner Intent Attribute"
        match_subclass = True
        id = 4
        len = 1
        fields_desc = P2PAttribute.fields_desc[:2] + [
            BitField("Intent", 0, 7),
            BitField("Tiebreaker", 0, 1)
        ]

class ConfigurationTimeoutAttribute(P2PAttribute):
        name = "Configuration Timeout Attribute"
        match_subclass = True
        id = 5
        len = 2
        fields_desc = P2PAttribute.fields_desc[:2] + [
            ByteField("GOConfigurationTimeout", 0),
            ByteField("ClientConfigurationTimeout", 0)
        ]

class ListenChannelAttribute(P2PAttribute):
        name = "Listen Channel Attribute"
        match_subclass = True
        id = 6
        len = 5
        fields_desc = P2PAttribute.fields_desc[:2] + [
            StrFixedLenField("Country", "XX", 3),
            ByteField("OperatingClass", 0),
            ByteField("ChannelNumber", 0)
        ]

class P2PGroupBSSIDAttribute(P2PAttribute):
        name = "P2P Group BSSID Attribute"
        match_subclass = True
        id = 7
        len = 6
        fields_desc = P2PAttribute.fields_desc[:2] + [
            NBytesField("P2PGroupBSSID", 0, 6)
        ]

class ExtendedListenTimingAttribute(P2PAttribute):
        name = "Extended Listen Timing Attribute"
        match_subclass = True
        id = 8
        len = 4
        fields_desc = P2PAttribute.fields_desc[:2] + [
            XShortField("AvailabilityPeriod", 0),
            XShortField("AvailabilityInterval", 0)
        ]

class IntendedP2PInterfaceAddressAttribute(P2PAttribute):
        name = "Intended P2P Interface Address Attribute"
        match_subclass = True
        id = 9
        len = 6
        fields_desc = P2PAttribute.fields_desc[:2] + [
            MACField("P2PInterfaceAddress", 0)
        ]

class P2PManageabilityAttribute(P2PAttribute):
        name = "P2P Manageability Attribute"
        match_subclass = True
        id = 10
        len = 1
        fields_desc = P2PAttribute.fields_desc[:2] + [
            ByteField("ManageabilityBitmap", 0),
            # FlagsField("ManageabilityBitmap", 0, 8, {
            #     0: "P2P Device Management",
            #     1: "Cross Connection Permitted",
            #     2: "Coexistence Optional"
            # })
        ]

class ChannelListAttribute(P2PAttribute):
        name = "Channel List Attribute"
        match_subclass = True
        id = 11
        fields_desc = P2PAttribute.fields_desc[:2] + [
            StrFixedLenField("Country", "XX", 3),
            PacketListField("ChannelEntryList", [], ChannelEntry, length_from=lambda pkt:pkt.len -3)
        ]


class NoticeOfAbsenceAttribute(P2PAttribute):
        name = "Notice Of Absence Attribute"
        match_subclass = True
        id = 12
        fields_desc = P2PAttribute.fields_desc[:2] + [
            ByteField("Index", 0),
            BitField("OppPS", 0, 1),
            BitField("CTWindow", 0, 7),
            PacketListField("NoticeofAbsenceDescriptors", [], NoticeOfAbsenceDescriptor,
                                         count_from = lambda pkt: (pkt.len - 2)/13)

        ]

class P2PDeviceInfoAttribute(P2PAttribute):
        name = "P2P Device Info Attribute"
        match_subclass = True
        id = 13
        fields_desc = P2PAttribute.fields_desc[:2] + [
            MACField("P2PDeviceAddress", 0),
            ShortEnumField("ConfigMethods", 0x1000, configuration_methods),
            PacketField("PrimaryDeviceType", PrimaryDeviceTypeData(), PrimaryDeviceTypeData),
            ByteField("number_of_secondary_device_types", 0),
            PacketListField("SecondaryDeviceTypeList", [], SecondaryDeviceTypeData,
                                         count_from = lambda pkt: pkt.number_of_secondary_device_types),
            PacketField("DeviceName", None, DeviceName)
        ]

class P2PGroupInfoAttribute(P2PAttribute):
        name = "P2P Group Info Attribute"
        match_subclass = True
        id = 14
        fields_desc = P2PAttribute.fields_desc[:2] + [
            PacketListField("P2PClientInfoDescriptor", [], P2PClientInfoDescriptor)
        ]


class P2PGroupIDAttribute(P2PAttribute):
        name = "P2P Group ID Attribute"
        match_subclass = True
        id = 15
        fields_desc = P2PAttribute.fields_desc[:2] + [
            MACField("P2P_device_address", 0),
            # PacketField("SSIDElement", None, SSIDElement)
            StrLenField("SSIDElement", "DIRECT-", length_from=lambda pkt:pkt.len-6)

        ]

class P2PInterfaceAttribute(P2PAttribute):
        name = "P2P Interface Attribute"
        match_subclass = True
        id = 16
        fields_desc = P2PAttribute.fields_desc[:2] + [
            NBytesField("P2P_DeviceAddress", 0, 6),
            FieldLenField("Count", None, count_of="P2PInterfaceAddressList"),
            FieldListField("P2PInterfaceAddressList", [], NBytesField("P2P Interface Address", 0, 6),
                    count_from = lambda pkt: pkt.Count)
        ]

class OperatingChannelAttribute(P2PAttribute):
        name = "Operating Channel Attribute"
        match_subclass = True
        len = 5
        id = 17
        fields_desc = P2PAttribute.fields_desc[:2] + [
            StrFixedLenField("country", "XX", 3),
            ByteField("OperatingClass", 0),
            ByteField("ChannelNumber", 0)
        ]

class InvitationFlagsAttribute(P2PAttribute):
        name = "Invitation Flags Attribute"
        match_subclass = True
        id = 18
        len = 1
        fields_desc = P2PAttribute.fields_desc[:2] + [
            BitField("Reserved", 0, 7),
            BitField("InvitationType", 0, 1)
        ]

class OutOfBandGroupOwnerNegotiationChannelAttribute(P2PAttribute):
        name = "Out Of Band Group Owner Negotiation Channel Attribute"
        match_subclass = True
        id = 19
        len = 6
        fields_desc = P2PAttribute.fields_desc[:2] + [
            StrFixedLenField("Country", "", 3),
            ByteField("operating_class", 0),
            ByteField("ChannelNumber", 0),
            ByteEnumField("RoleIndication", 0, role_indication)
        ]

class ServiceHashAttribute(P2PAttribute):
        name = "Service Hash Attribute"
        match_subclass = True
        id = 21
        fields_desc = P2PAttribute.fields_desc[:2] + [
            PacketListField("ServiceHash", [], NBytesField("Service Hash", 0, 6),
                                         count_from = lambda pkt: pkt.len/6)
        ]

class SessionInformationDataInfo(P2PAttribute):
        name = "Session Information Data Info"
        match_subclass = True
        id = 22
        fields_desc = P2PAttribute.fields_desc[:2] + [
            StrLenField("session_information", "", length_from=lambda pkt:pkt.len)
        ]

class ConnectionCapabilityInfoAttribute(P2PAttribute):
        name = "Connection Capability Info Attribute"
        match_subclass = True
        id = 23
        len = 1
        fields_desc = P2PAttribute.fields_desc[:2] + [
            ByteEnumField("ConnectionCapability", 0, connection_capabilities)
        ]


class AdvertisementIDInfoAttribute(P2PAttribute):
        name = "Advertisement ID Info Attribute"
        match_subclass = True
        id = 24
        len = 10
        fields_desc = P2PAttribute.fields_desc[:2] + [
            XIntField("AdvertisementID", 0),
            MACField("ServiceMACAddress", 0)
        ]

class AdvertisedServiceInfoAttribute(P2PAttribute):
        name = "Advertised Service Info Attribute"
        match_subclass = True
        id = 25
        fields_desc = P2PAttribute.fields_desc[:2] + [
            PacketListField("AdvertisedServiceDescriptor", [], AdvertisedServiceDescriptor)
        ]

class SessionIDInfoAttribute(P2PAttribute):
        name = "Session ID Info Attribute"
        match_subclass = True
        id = 26
        len = 10
        fields_desc = P2PAttribute.fields_desc[:2] + [
            XIntField("SessionID", 0),
            MACField("SessionMACAddress", 0)
        ]

class FeatureCapabilityInfoAttribute(P2PAttribute):
        name = "Feature Capability Info Attribute"
        match_subclass = True
        id = 27
        fields_desc = P2PAttribute.fields_desc[:2] + [
            StrLenField("FeatureCapability", "", length_from=lambda pkt:pkt.len)
        ]

class PersistentGroupInfoAttribute(P2PAttribute):
        name = "Persistent Group Info Attribute"
        match_subclass = True
        id = 28
        fields_desc = P2PAttribute.fields_desc[:2] + [
            NBytesField("P2PDeviceAddress", 0, 6),
            PacketField("SSID", None, SSIDElement)
        ]

class Dot11EltWiFiAllianceP2P(Dot11EltVendorSpecific):
    name = "802.11 Wi-Fi Alliance P2P"
    match_subclass = True
    ID = 221
    oui = 0x506f9a
    show_indent = 0
    fields_desc = Dot11EltVendorSpecific.fields_desc[:3] + [
        XByteField("type", 0x09),
        PacketListField(
            "P2PAttributes",
            [],
            P2PAttribute,
            length_from=lambda x: x.len-4
        )
    ]

class Dot11PublicAction(_Dot11EltUtils):
    name = "802.11 Public Action"
    fields_desc = [ByteField("Category", 0x04),
                   ByteField("ActionField", 0x09),
                   OUIField("oui", 0x506F9A),
                   ByteField("OUItype", 0x09),
                   ByteEnumField("OUISubtype", 0, p2p_public_action_frame_type),
                   ByteField("DialogToken", 1)
                   ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            oui = struct.unpack("!I", b"\x00" + _pkt[2:5])[0]
        if oui == 0x506f9a: # Wi-Fi Alliance
                type_ = orb(_pkt[5])
                if type_ == 0x09:
                    # Wi-Fi Alliance P2P IE
                    subtype_ = orb(_pkt[6])
                    if subtype_ == 0:
                        return GONegotiatioRequest
                    elif subtype_ == 1:
                        return GONegotiationResponse
                    elif subtype_ == 2:
                        return GONegotiationConfirmation
                    elif subtype_ == 3:
                        return P2PInvitationRequest
                    elif subtype_ == 4:
                        return P2PInvitationResponse
                    elif subtype_ == 7:
                        return P2PProvisionDiscoveryRequest
                    elif subtype_ == 8:
                        return P2PProvisionDiscoveryResponse
                return Dot11EltVendorSpecific
        return cls

class GONegotiatioRequest(Dot11PublicAction):
      name = "GO Negotiation Request"
      OUISubtype = 0

class GONegotiationResponse(Dot11PublicAction):
      name = "GO Negotiation Response"
      OUISubtype = 1

class GONegotiationConfirmation(Dot11PublicAction):
      name = "GO Negotiation Confirmation"
      OUISubtype = 2

class P2PInvitationRequest(Dot11PublicAction):
      name = "P2P Invitation Request"
      OUISubtype = 3

class P2PInvitationResponse(Dot11PublicAction):
      name = "P2P Invitation Response"
      OUISubtype = 4

class P2PProvisionDiscoveryRequest(Dot11PublicAction):
      name = "Provision Discovery Request"
      OUISubtype = 7

class P2PProvisionDiscoveryResponse(Dot11PublicAction):
      name = "Provision Discovery Response"
      OUISubtype = 8

bind_layers(Dot11PublicAction, Dot11EltWiFiAllianceP2P)
bind_layers(Dot11Elt, Dot11EltWiFiAllianceP2P)
bind_layers(Dot11EltWiFiAllianceP2P, P2PAttribute)
bind_layers(P2PAttribute, P2PAttribute)
bind_layers(Dot11, Dot11PublicAction, subtype=13, type=0)
bind_layers(ChannelEntry, ChannelEntry)
bind_layers(ChannelEntry, P2PAttribute)
