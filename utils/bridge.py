import os
if "SOCKET_PROXY_HOST" in os.environ:
    from scapy.all import *
    from socket_hook_py import *
    from scapy.layers.dot11 import Dot11

    # new_send
    def new_send(x: Dot11, iface=None, **kargs):
        def inner_send(x: Dot11):
            raw_send(x, iface=iface, **kargs)
        my_send(inner_send, x)

    # new sendp
    def new_sendp(x, iface=None, **kargs):
        def inner_sendp(x):
            raw_sendp(x, iface=iface, **kargs)
        my_send(inner_sendp, x)

    raw_sendp = sendp
    sendp = new_sendp
    raw_send = send
    send = new_send

    # new sniff
    def new_sniff(*args, **kargs):
        data = raw_sniff(*args, **kargs)
        if len(data) != 0:
            for i in range(len(data)):
                my_sniff(data[i])
        return data

    raw_sniff = sniff
    sniff = new_sniff

