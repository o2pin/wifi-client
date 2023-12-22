from scapy.fields import ByteEnumField, ByteField, NBytesField, PacketListField, ShortEnumField, ShortField, StrLenField, XByteField
from scapy.packet import Packet, bind_layers
from scapy.fields import FieldLenField, LEShortField
from .dot11 import Dot11EltVendorSpecific
from .dot11p2p import Dot11EltWiFiAllianceP2P

wps_attribute_id_definitions = {
    0x1062: "802.1X Enabled",
    0x1001: "AP Channel",
    0x1057: "AP Setup Locked",
    0x1058: "Application Extension",
    0x1063: "AppSessionKey",
    0x1002: "Association State",
    0x1003: "Authentication Type",
    0x1004: "Authentication Type Flags",
    0x1005: "Authenticator",
    0x1072: "Available IPv4 Submask List",
    0x1009: "Configuration Error",
    0x1008: "Configuration Methods",
    0x100A: "Confirmation URL4",
    0x100B: "Confirmation URL6",
    0x100C: "Connection Type",
    0x100D: "Connection Type Flags",
    0x100E: "Credential",
    0x1011: "Device Name",
    0x1012: "Device Password ID",
    0x104D: "EAP Identity",
    0x1059: "EAP Type",
    0x1014: "E-Hash1",
    0x1015: "E-Hash2",
    0x1018: "Encrypted Settings",
    0x100F: "Encryption Type",
    0x1010: "Encryption Type Flags",
    0x1071: "Enrollee IPv4 Address",
    0x101A: "Enrollee Nonce",
    0x106D: "Entry Acceptable (only for IBSS)",
    0x1016: "E-SNonce1",
    0x1017: "E-SNonce2",
    0x101B: "Feature ID",
    0x101C: "Identity",
    0x101D: "Identity Proof",
    0x1060: "Initialization Vector",
    0x1073: "IP Address Configuration Methods",
    0x1070: "IPv4 Subnet Mask",
    0x101F: "Key Identifier",
    0x1051: "Key Lifetime",
    0x1061: "Key Provided Automatically",
    0x101E: "Key Wrap Authenticator",
    0x1020: "MAC Address",
    0x1021: "Manufacturer",
    0x104E: "Message Counter",
    0x1022: "Message Type",
    0x1023: "Model Name",
    0x1024: "Model Number",
    0x1026: "Network Index",
    0x1027: "Network Key",
    0x1028: "Network Key Index (reserved)",
    0x1029: "New Device Name",
    0x102A: "New Password",
    0x102C: "Out-of-Band Device Password",
    0x102D: "OS Version",
    0x1052: "Permitted Configuration Methods",
    0x1056: "Portable Device",
    0x102F: "Power Level",
    0x1054: "Primary Device Type",
    0x1030: "PSK Current",
    0x1031: "PSK Max",
    0x1032: "Public Key",
    0x104F: "Public Key Hash",
    0x1033: "Radio Enabled",
    0x1034: "Reboot",
    0x1035: "Registrar Current",
    0x1036: "Registrar Established",
    0x106F: "Registrar IPv4 Address",
    0x1037: "Registrar List",
    0x1038: "Registrar Max",
    0x1039: "Registrar Nonce",
    0x106E: "Registration Ready (only for IBSS)",
    0x1050: "Rekey Key",
    0x103A: "Request Type",
    0x106A: "Requested Device Type",
    0x103B: "Response Type",
    0x103C: "RF Bands",
    0x103D: "R-Hash1",
    0x103E: "R-Hash2",
    0x103F: "R-SNonce1",
    0x1040: "R-SNonce2",
    0x1055: "Secondary Device Type List",
    0x1041: "Selected Registrar",
    0x1053: "Selected Registrar Configuration Methods",
    0x1042: "Serial Number",
    0x1045: "SSID",
    0x1046: "Total Networks",
    0x1047: "UUID-E",
    0x1048: "UUID-R",
    0x1049: "Vendor Extension",
    0x104A: "Version",
    0x1064: "WEPTransmitKey",
    0x1044: "Wi-Fi Simple Configuration State",
    0x104C: "X.509 Certificate",
    0x104B: "X.509 Certificate Request"
}

request_type_value = {
    0x00: "Enrollee, Info only",
    0x01: "Enrollee, open 802.1X",
    0x02: "Registrar",
    0x03: "WLAN Manager Registrar"
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

RF_band_value = {
    0x01: "2.4GHz",
    0x02: "5.0GHz",
    0x03: "2.4 and 5.0GHz",
    0x04: "60GHz"
}

association_state_values = {
    0: "Not Associated",
    1: "Connection Success",
    2: "Configuration Failure",
    3: "Association Failure",
    4: "IP Failure"
}

configuration_error = {
    0: "No Error",
    1: "Out-of-Band Interface Read Error",
    2: "Decryption CRC Failure",
    3: "2.4 channel not supported",
    4: "5.0 channel not supported",
    5: "Signal too weak",
    6: "Network auth failure",
    7: "Network association failure",
    8: "No DHCP response",
    9: "Failed DHCP config",
    10: "IP address conflict",
    11: "Couldn’t connect to Registrar",
    12: "Multiple PBC sessions detected",
    13: "Rogue activity suspected",
    14: "Device busy",
    15: "Setup locked",
    16: "Message Timeout",
    17: "Registration Session Timeout",
    18: "Device Password Auth Failure",
    19: "60 GHz channel not supported",
    20: "Public Key Hash Mismatch"
}

device_password_ID = {
      0x0000: "Default (PIN)",
      0x0001: "User-specified",
      0x0002: "Machine-specified",
      0x0003: "Rekey",
      0x0004: "Pushbutton",
      0x0005: "Registrar-specified",
      0x0006: "Reserved (for IBSS with Wi-Fi Protected Setup Specification)",
      0x0007: "NFC-Connection-Handover",
      0x0008: "P2Ps (Reserved for Wi-Fi Peer-to-Peer Services Specification)"
}

response_type = {
      0x00: "Enrollee, Info only",
      0x01: "Enrollee, open 802.1X",
      0x02: "Registrar",
      0x03: "AP",
      0x04: "Reserved (for IBSS with Wi-Fi Protected Setup Specification)"
}
class WPSAttribute(Packet):
    name = "WPS Attribute"
    match_subclass = True
    show_indent = 0
    fields_desc = [
        ShortEnumField("id", 0, wps_attribute_id_definitions),
        ShortField("len", None),
        StrLenField("body", "", length_from=lambda x: x.len)
    ]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            id = _pkt[0] * 16 * 16 + _pkt[1]
            if id == 0x104a:
                return VersionAttribute
            if id == 0x1044:
                return WiFiSimpleConfigurationStateAttribute
            if id == 0x103A:
                return RequestTypeAttribute
            if id == 0x103B:
                return ResponseTypeAttribute
            if id == 0x1008:
                return ConfigurationMethodsAttribute
            if id == 0x1047:
                return UUIDEAttribute
            if id == 0x1054:
                return PrimaryDeviceTypeAttribute
            if id == 0x103C:
                return RFBandsAttribute
            if id == 0x1002:
                return AssociationStateAttribute
            if id == 0x1009:
                return ConfigurationErrorAttribute
            if id == 0x1012:
                return DevicePasswordIDAttribute
            if id == 0x1021:
                return ManufacturerAttribute
            if id == 0x1023:
                return ModelNameAttribute
            if id == 0x1024:
                return ModelNumberAttribute
            if id == 0x1011:
                return DeviceNameAttribute
            if id == 0x1042:
                return SerialNumberAttribute
            return cls
        return cls

class VersionAttribute(WPSAttribute):
        name = "Version Attribute"
        match_subclass = True
        id = 0x104a
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            XByteField("Version", 0)
        ]

class WiFiSimpleConfigurationStateAttribute(WPSAttribute):
        name = "Wi-Fi Simple Configuration State Attribute"
        match_subclass = True
        id = 0x1044
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteField("State", 0)
        ]

class RequestTypeAttribute(WPSAttribute):
        name = "Request Type Attribute"
        match_subclass = True
        id = 0x103A
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteEnumField("RequestType", 0, request_type_value)
        ]

class ResponseTypeAttribute(WPSAttribute):
        name = "Response Type Attribute"
        match_subclass = True
        id = 0x103B
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteEnumField("ResponseType", 0, response_type)
        ]

class ConfigurationMethodsAttribute(WPSAttribute):
        name = "Configuration Methods Attribute"
        match_subclass = True
        id = 0x1008
        len = 2
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ShortEnumField("ConfigurationMethods", 0, configuration_methods),
        ]

class UUIDEAttribute(WPSAttribute):
        name = "UUID-E Attribute"
        match_subclass = True
        id = 0x1047
        len = 16
        fields_desc = WPSAttribute.fields_desc[:2] + [
            NBytesField("UUIDE", 0, 16)
        ]

class PrimaryDeviceTypeAttribute(WPSAttribute):
        name = "Primary Device Type Attribute"
        match_subclass = True
        id = 0x1054
        len = 8
        fields_desc = WPSAttribute.fields_desc[:2] + [
            NBytesField("PrimaryDeviceType", 0, 8)
        ]

class RFBandsAttribute(WPSAttribute):
        name = "RF Bands Attribute"
        match_subclass = True
        id = 0x103C
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteEnumField("RFBands", 0, RF_band_value)
        ]

class AssociationStateAttribute(WPSAttribute):
        name = "Association State Attribute"
        match_subclass = True
        id = 0x1002
        len = 2
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ShortEnumField("AssociationState", 0, association_state_values),
        ]

class ConfigurationErrorAttribute(WPSAttribute):
        name = "Configuration Error Attribute"
        match_subclass = True
        id = 0x1009
        len = 2
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ShortEnumField("ConfigurationError", 0, configuration_error),
        ]

class DevicePasswordIDAttribute(WPSAttribute):
        name = "Device Password ID Attribute"
        match_subclass = True
        id = 0x1012
        len = 2
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ShortEnumField("DevicePasswordID", 0, device_password_ID),
        ]

class ManufacturerAttribute(WPSAttribute):
        name = "Manufacturer Attribute"
        match_subclass = True
        id = 0x1021
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteField("Manufacturer", 0)
        ]

class ModelNameAttribute(WPSAttribute):
        name = "Model Name Attribute"
        match_subclass = True
        id = 0x1023
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteField("ModelName", 0)
        ]

class ModelNumberAttribute(WPSAttribute):
        name = "Model Number Attribute"
        match_subclass = True
        id = 0x1024
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteField("ModelNumber", 0)
        ]

class DeviceNameAttribute(WPSAttribute):
        name = "Device Name Attribute"
        match_subclass = True
        id = 0x1011
        fields_desc = WPSAttribute.fields_desc[:1] + [
            FieldLenField("len", None, length_of="DeviceName"),
            StrLenField("DeviceName", 0, length_from=lambda x: x.len)
        ]

class SerialNumberAttribute(WPSAttribute):
        name = "Serial Number Attribute"
        match_subclass = True
        id = 0x1042
        len = 1
        fields_desc = WPSAttribute.fields_desc[:2] + [
            ByteField("SerialNumber", 0)
        ]

# class VendorExtensionAttribute(WPSAttribute):
#         name = "Vendor Extension Attribute"
#         match_subclass = True
#         id = 0x1049
#         len = 1
#         fields_desc = WPSAttribute.fields_desc[:2] + [
#             ByteField("DeviceName", 0)
#         ]

class Dot11EltWPS(Dot11EltVendorSpecific):
    name = "802.11 Microsoft WPS"
    match_subclass = True
    ID = 221
    oui = 0x0050f2
    show_indent = 0
    fields_desc = Dot11EltVendorSpecific.fields_desc[:3] + [
        XByteField("type", 0x04)
    ] + [
        PacketListField(
        "WPSAttributes",
        [],
        WPSAttribute,
        length_from=lambda x: x.len-4
    )
    ]

bind_layers(Dot11EltWPS, WPSAttribute)
bind_layers(WPSAttribute, WPSAttribute)
bind_layers(Dot11EltWPS, Dot11EltWiFiAllianceP2P)