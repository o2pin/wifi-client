from scapy.all import *

from socket_hook_py import *
from scapy.layers.dot11 import Dot11, RadioTap

# new_send
def new_send(x: Dot11, iface=None, **kargs):
    # subtype = x[Dot11].subtype
    # type_ = x[Dot11].type
    # fcfield = x[Dot11].FCfield
    # id = x[Dot11].ID
    # addr1 = x[Dot11].addr1
    # addr2 = x[Dot11].addr2
    # addr3 = x[Dot11].addr3
    # sc = x[Dot11].SC
    def correct_addr1_send(x: Dot11, iface=None, **kargs):
        # 不修改变异后的的数据包, 修改会导致保存的和实际发送的不一致, 复现会有问题
        # x[Dot11].addr1 = addr1
        raw_send(x, iface=None, **kargs)

    my_send(correct_addr1_send, x, iface=iface, **kargs)

raw_send = send
send = new_send

# new sniff 当前预期适用于sniff仅接收一个回包
def new_sniff(*args, **kargs):
    data = raw_sniff(*args, **kargs)
    if len(data) != 0:
        data = data[0]
        my_sniff(data)
    return data

raw_sniff = sniff
sniff = new_sniff

# new sendp
def new_sendp(x, iface=None, **kargs):
    def correct_addr1_sendp(x: Dot11, iface=None, **kargs):
        # 不修改变异后的的数据包, 修改会导致保存的和实际发送的不一致, 复现会有问题
        # x[Dot11].addr1 = addr1
        pkt = RadioTap() / x
        raw_sendp(pkt, iface=iface, **kargs)

    if x.haslayer(RadioTap):
        x = x.getlayer(Dot11)
    my_sendp(correct_addr1_sendp, x, iface=iface, **kargs)

raw_sendp = sendp
sendp = new_sendp
