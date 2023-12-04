from scapy.all import *

from socket_hook_py import *

# new_send
def new_send(x, iface=None, **kargs):
    my_send(raw_send, x, iface=iface, **kargs)

raw_send = send
send = new_send

# new sniff 当前预期适用于sniff仅接收一个回包
def new_sniff(*args, **kargs):
    data = raw_sniff(*args, **kargs)
    if data is not None:
        data = data[0]
        my_sniff(data)
    return data

raw_sniff = sniff
sniff = new_sniff

# new sendp
def new_sendp(x, iface=None, **kargs):
    my_sendp(raw_sendp, x, iface=iface, **kargs)

raw_sendp = sendp
sendp = new_sendp
