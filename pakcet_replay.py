from scapy.all import *


smylguest = "5a41201d26ed" 
ztkj = "206be7a3fca0" 

rt3070 = "00a1b07903f6"
mtk7921au = "001d4320192d"

z = ztkj + mtk7921au + ztkj
s = smylguest + rt3070  + smylguest

# auth = bytes.fromhex(
#     "000012002e48000000028509a000ef010000b0003a01" + s + "1000000001000000"
#     )
# assocation = bytes.fromhex(
#     "000012002e48000000028509a000ef01000000003a01" + s + "b0001100fa000011736875696d7579756c696e2d6775657374010882848b960c1218242d1a621917ff0000000000000000000000000000000000000000000030160100000fac040100000fac040100000fac023c00000032043048606c7f0800008080014000c07f080000000000000040dd070050f202000100"
#     )

# a= RadioTap(assocation)
# a.display()

# print(a[Dot11Elt].info)

# sendp(auth , iface="wlan0mon")
# sendp(a , iface="wlan0mon")



auth = bytes.fromhex(
    "000012002e48000000028509a000ef010000b0003a01" + z + "1000000001000000"
    )
assocation = bytes.fromhex(
    "000012002e48000000028509a000ef01000000003a01" + z + "b0001100fa000011736875696d7579756c696e2d6775657374010882848b960c1218242d1a621917ff0000000000000000000000000000000000000000000030160100000fac040100000fac040100000fac023c00000032043048606c7f0800008080014000c07f080000000000000040dd070050f202000100"
    )

a= RadioTap(assocation)
print(a[Dot11Elt])

print(a[Dot11Elt].info)
a[Dot11Elt].info=b"ztkj"
a[Dot11Elt].len=4
print(a[Dot11Elt].info)
sendp(auth , iface="wlan1mon")
sendp(a , iface="wlan1mon")

