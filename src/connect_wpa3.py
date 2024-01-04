# TODO: For now only include the code we actually used for EAP-pwd
# TODO: Program unit tests so we can easily keep our EAP-pwd code correct
#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dot11 import Dot11Auth,Dot11Deauth, Dot11, RadioTap, Dot11AssoReq, Dot11Elt, Dot11EltRSN, RSNCipherSuite,AKMSuite, Dot11QoS ,LLC 
from scapy.layers.l2    import SNAP
from scapy.contrib.wpa_eapol import *
from .libwifi import *
import sys, struct, math, random, select, time, binascii

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Math.Numbers import Integer

from socket_hook_py import sendp, sniff 
# Alternative is https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python
from sympy.ntheory.residue_ntheory import sqrt_mod_iter

from .utils_wpa3_crypt import Calc_MIC, GTKDecrypt, Generate_Plain_text, CCMPCrypto
from .utils_wifi_inject import Dot11EltRates

# ----------------------- Utility ---------------------------------

class SAE(Packet):
    name = "SAE"
    fields_desc = [
        # Add the WPA3_SAE fields
        ShortEnumField("groupid", 19, {19: "SAE"}),  # groupid is 2 bytes
        StrFixedLenField("scalar", "", 32),
        StrFixedLenField("ffe", "", 64)
    ]


class WiFi_Object:
    def __init__(self, iface, ssid, psk, mac_ap="", mac_sta="", anonce="", snonce="", payload="", mic="", kck=b"", pmk=b""):
        self.iface:str  = iface
        self.ssid:str  = ssid
        self.psk:str  = psk
        self.mac_ap:str  = mac_ap
        self.mac_sta:str  = mac_sta
        self.ff_mac:str  = "ff:ff:ff:ff:ff:ff"
        self.anonce:bytes = bytes.fromhex(anonce)
        self.snonce:bytes = bytes.fromhex(snonce)
        self.payload:bytes = bytes.fromhex(payload)
        self.mic:str = "0" * 32     # bytes
        self.kck : bytes = kck
        self.pmk:bytes = pmk
        self.ptk:str = "0" * 40
        self.encrypt_msg:bytes = "0" * 56



def int_to_data(num):
    return binascii.unhexlify("%064x" % num)

def zeropoint_to_data():
    return int_to_data(0) + int_to_data(0)

#TODO: Not sure if this actually works under python2...
def str2bytes(password):
    if not isinstance(password, str): return password
    if sys.version_info < (3, 0):
        return bytes(password)
    else:
        return bytes(password, 'utf8')

def getord(value):
    if isinstance(value, int):
        return value
    else:
        return ord(value)

def HMAC256(pw, data):
    h = HMAC.new(pw, digestmod=SHA256)
    h.update(data)
    return h.digest()


# ----------------------- Elliptic Curve Operations ---------------------------------

# This is group 19. Support of it is required by WPA3.
# “secp256r1”是SECG（高效密码学组织标准）选择和推荐的特定椭圆曲线和相关域参数。请参阅 https://www.secg.org/sec2-v2.pdf 上的“SEC 2：推荐的椭圆曲线域参数”。
secp256r1_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
# 115792089210356248762697446949407573530086143415290314195533631308867097853951
secp256r1_r = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
# 115792089210356248762697446949407573529996955224135760342422259061068512044369

def legendre_symbol(a, p):
    """Compute the Legendre symbol."""
    if a % p == 0: return 0

    ls = pow(a, (p - 1)//2, p)
    return -1 if ls == p - 1 else ls

def point_on_curve(x, y, curve="p256"):
    try:
        point = ECC.EccPoint(x, y)
    except ValueError:
        return False
    return True

def point_to_data(p):
    if p is None:
        return zeropoint_to_data()
    return int_to_data(p.x) + int_to_data(p.y)


# ----------------------- WPA3 ---------------------------------

def is_sae(p):
    if not Dot11Auth in p:
        return False
    return p[Dot11Auth].algo == 3

def is_sae_commit(p):
    return is_sae(p) and p[Dot11Auth].seqnum == 1

def is_sae_confirm(p):
    return is_sae(p) and p[Dot11Auth].seqnum == 2

def KDF_Length(data, label, context, length):
    iterations = int(math.ceil(length / 256.0))
    result = b""
    for i in range(1, iterations + 1):
        hash_data = struct.pack("<H", i) + str2bytes(label) + context + struct.pack("<H", length)
        result += HMAC256(data, hash_data)
    return result

# TODO: Also modify to support curve 521
def derive_pwe_ecc(password, addr1, addr2, curve_name="p256"):
    curve = ECC._curves[curve_name]
    bits = curve.modulus_bits
    assert bits % 8 == 0

    addr1 = binascii.unhexlify(addr1.replace(':', ''))
    addr2 = binascii.unhexlify(addr2.replace(':', ''))
    hash_pw = addr1 + addr2 if addr1 > addr2 else addr2 + addr1

    for counter in range(1, 100):
        hash_data = str2bytes(password) + struct.pack("<B", counter)
        pwd_seed = HMAC256(hash_pw, hash_data)
        log(DEBUG, "PWD-seed: %s" % pwd_seed)
        pwd_value = KDF_Length(pwd_seed, "SAE Hunting and Pecking", curve.p.to_bytes(bits // 8), bits)
        log(DEBUG, "PWD-value: %s" % pwd_value)
        pwd_value = int(binascii.hexlify(pwd_value), 16)

        if pwd_value >= curve.p:
            continue
        x = Integer(pwd_value)

        y_sqr = (x**3 - x * 3 + curve.b) % curve.p
        if legendre_symbol(y_sqr, curve.p) != 1:
            continue

        y = y_sqr.sqrt(curve.p)
        y_bit = getord(pwd_seed[-1]) & 1
        if y & 1 == y_bit:
            return ECC.EccPoint(x, y, curve_name)
        else:
            return ECC.EccPoint(x, curve.p - y, curve_name)


# TODO: Use this somewhere???
def calc_k_kck_pmk(pwe, peer_element, peer_scalar, my_rand, my_scalar):
    k = ((pwe * peer_scalar + peer_element) * my_rand).x

    keyseed = HMAC256(b"\x00" * 32, int_to_data(k))
    kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK",
                             int_to_data((my_scalar + peer_scalar) % secp256r1_r), 512)
    kck = kck_and_pmk[0:32]
    pmk = kck_and_pmk[32:]

    return k, kck, pmk


def calculate_confirm_hash(kck, send_confirm, scalar, element, peer_scalar, peer_element):
    return HMAC256(kck, struct.pack("<H", send_confirm) + int_to_data(scalar) + point_to_data(element)
                        + int_to_data(peer_scalar) + point_to_data(peer_element))

def build_sae_commit(srcaddr, dstaddr, scalar, element, token=""):
    p = Dot11(addr1=dstaddr, addr2=srcaddr, addr3=dstaddr)
    p = p/Dot11Auth(algo=3, seqnum=1, status=0)

    group_id = 19
    scalar_blob = bytes.fromhex("%064x" % scalar)
    element_blob = bytes.fromhex("%064x" % element.x) + bytes.fromhex("%064x" % element.y)

    return p/Raw(struct.pack("<H", group_id) + bytes.fromhex(token) + scalar_blob + element_blob)


def build_sae_confirm(srcaddr, dstaddr, send_confirm, confirm):
    p = Dot11(addr1=dstaddr, addr2=srcaddr, addr3=dstaddr)
    p = p/Dot11Auth(algo=3, seqnum=2, status=0)

    return p/Raw(struct.pack("<H", send_confirm) + confirm)


class SAEHandshake():
    def __init__(self, password, srcaddr, dstaddr):
        self.password = password
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr

        self.pwe = None
        self.rand = None
        self.scalar = None
        self.element = None
        self.kck = None
        self.pmk = None

    def send_commit(self):
        self.pwe = derive_pwe_ecc(self.password, self.dstaddr, self.srcaddr)

        # After generation of the PWE, each STA shall generate a secret value, rand, and a temporary secret value,
        # mask, each of which shall be chosen randomly such that 1 < rand < r and 1 < mask < r and (rand + mask)
        # mod r is greater than 1, where r is the (prime) order of the group.
        self.rand = random.randint(0, secp256r1_r - 1)
        mask = random.randint(0, secp256r1_r - 1)

        # commit-scalar = (rand + mask) mod r
        self.scalar = (self.rand + mask) % secp256r1_r
        assert self.scalar > 1

        # COMMIT-ELEMENT = inverse(mask * PWE)
        temp = self.pwe * mask
        self.element = ECC.EccPoint(temp.x, Integer(secp256r1_p) - temp.y)

        sae_commit_1 = build_sae_commit(self.srcaddr, self.dstaddr, self.scalar, self.element)
        

        return sae_commit_1

    def process_commit(self, p):
        self.peer_scalar = int.from_bytes(p.scalar, byteorder='big')
        peer_element_x = int.from_bytes(p.ffe[:32], byteorder='big')
        peer_element_y = int.from_bytes(p.ffe[32:], byteorder='big')
        self.peer_element = ECC.EccPoint(peer_element_x, peer_element_y)

        k = ((self.pwe * self.peer_scalar + self.peer_element) * self.rand).x

        keyseed = HMAC256(b"\x00"*32, int_to_data(k))
        kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK",
                                 int_to_data((self.scalar + self.peer_scalar) % secp256r1_r), 512)
        self.kck = kck_and_pmk[0:32]
        self.pmk = kck_and_pmk[32:]
        # print("KCK : ", self.kck)
        # print("PMK : ", self.pmk)

        return self.kck, self.pmk

    def send_confirm(self, iface):
        send_confirm = 0
        confirm = calculate_confirm_hash(self.kck, send_confirm, self.scalar, self.element, self.peer_scalar, self.peer_element)

        auth = build_sae_confirm(self.srcaddr, self.dstaddr, send_confirm, confirm)
        sendp(RadioTap()/auth, iface=iface)

    def process_confirm(self, p):
        payload = str(p[Dot11Auth].payload)

        send_confirm = struct.unpack("<H", payload[:2])[0]
        pos = 2

        received_confirm = payload[pos:pos+32]
        pos += 32

        expected_confirm = calculate_confirm_hash(self.kck, send_confirm, self.peer_scalar, self.peer_element, self.scalar, self.element)


# ----------------------- EAP-pwd (TODO Test with Python3) ---------------------------------

def KDF_Length_eappwd(data, label, length):
    num_bytes = (length + 7) // 8
    iterations = (num_bytes + 31) // 32

    # TODO: EAP-pwd uses a different byte ordering for the counter and length?!? WTF!
    result = b""
    for i in range(1, iterations + 1):
        hash_data  = digest if i > 1 else b""
        hash_data += struct.pack(">H", i) + str2bytes(label) + struct.pack(">H", length)
        digest = HMAC256(data, hash_data)
        result += digest

    result = result[:num_bytes]
    if length % 8 != 0:
        num_clear = 8 - (length % 8)
        trailbyte = result[-1] >> num_clear << num_clear
        result = result[:-1] + struct.pack(">B", trailbyte)
    return result


def derive_pwe_ecc_eappwd(password, peer_id, server_id, token, curve_name="p256", info=None):
    curve = ECC._curves[curve_name]
    bits = curve.modulus_bits

    hash_pw = struct.pack(">I", token) + str2bytes(peer_id + server_id + password)
    for counter in range(1, 100):
        hash_data = hash_pw + struct.pack("<B", counter)
        pwd_seed = HMAC256(b"\x00", hash_data)
        log(DEBUG, "PWD-Seed: %s" % pwd_seed)
        pwd_value = KDF_Length_eappwd(pwd_seed, "EAP-pwd Hunting And Pecking", bits)
        log(DEBUG, "PWD-Value: %s" % pwd_value)
        pwd_value = int(binascii.hexlify(pwd_value), 16)

        if bits % 8 != 0:
            pwd_value = pwd_value >> (8 - (521 % 8))

        if pwd_value >= curve.p:
            continue
        x = Integer(pwd_value)

        log(DEBUG, "X-candidate: %x" % x)
        y_sqr = (x**3 - x * 3 + curve.b) % curve.p
        if legendre_symbol(y_sqr, curve.p) != 1:
            continue

        y = y_sqr.sqrt(curve.p)
        y_bit = getord(pwd_seed[-1]) & 1
        if y & 1 == y_bit:
            if not info is None: info["counter"] = counter
            return ECC.EccPoint(x, y, curve_name)
        else:
            if not info is None: info["counter"] = counter
            return ECC.EccPoint(x, curve.p - y, curve_name)


def calculate_confirm_eappwd(k, element1, scalar1, element2, scalar2, group_num=19, rand_func=1, prf=1):
    hash_data  = int_to_data(k)
    hash_data += point_to_data(element1)
    hash_data += int_to_data(scalar1)
    hash_data += point_to_data(element2)
    hash_data += int_to_data(scalar2)
    hash_data += struct.pack(">HBB", group_num, rand_func, prf)
    confirm = HMAC256(b"\x00" * 32, hash_data)
    return confirm


class RSN():
    def get_rsn_info(self):
        rsn_info = Dot11EltRSN(
                len=26,         # len=22  smyl / len=20 xiaomihotspot / len=26,wpa3
                group_cipher_suite=RSNCipherSuite(),
                nb_pairwise_cipher_suites=1,
                pairwise_cipher_suites=[RSNCipherSuite()],
                nb_akm_suites=1,
                akm_suites=[AKMSuite(suite=8)], # 重要, =8 代表 SAE
                mfp_required=0 ,    # 管理帧保护要求，=1 or =0, 受保护的管理帧强制对断开连接帧进行加密
                mfp_capable=1,    # 管理帧保护能力, =1 or =0
                gtksa_replay_counter=0 ,
                ptksa_replay_counter=0,
                # group_management_cipher_suite=0x000fac06   # 因为len=26，自动带入group 参数
                )

        return rsn_info

class eapol_handshake():
    def __init__(self, DUT_Object, rsn_info):
        self.config = DUT_Object
        self.eapol_3_found = False
        self.rsn_info = rsn_info

    def run(self):
        # Key (Message 1 of 4)
        logging.info("\n-------------------------Key (Message 1 of 4): ")
        eapol_p1 = sniff(iface=self.config.iface,
                         lfilter=lambda r: (r.haslayer(EAPOL) and (r.getlayer(WPA_key).key_info  == 0x0088)) ,
                         count=1, store=1, timeout=2, prn = lambda x: logging.debug(x))
        if len(eapol_p1) > 0:
            logging.info("成功捕获到 EAPOL Message 1 of 4 ")
        else:
            logging.error("未成功捕获到符合条件的 EAPOL Message 1 of 4 ")
            sys.exit(1)
        # # 提取 802.11 层 sequence
        # dot11_seq = eapol_p1[0].payload.SC
        # eapol_1_layer = eapol_p1[0].payload.payload.payload.payload
        # RadioTap / Dot11 / LLC / SNAP / EAPOL EAPOL-Key + **Raw**
        eapol_1_packet = eapol_p1[0][EAPOL]
        replay_counter = eapol_1_packet[WPA_key].replay_counter
        # 提取 anonce
        self.config.anonce = eapol_1_packet[WPA_key].nonce
        print("Anonce : ", (self.config.anonce).hex())
        logging.debug("ANonce {}".format((self.config.anonce).hex()))

        # Key (Message 2 of 4)
        logging.debug("-------------------------Key (Message 2 of 4): ")
        # 计算 MIC
        self.config.snonce = randstring(32)
        eapol_2 = EAPOL(version=1, type=3, len=123) / WPA_key(      # len 适应wpa3
                        descriptor_type=2,
                        key_info=0x0108,
                        replay_counter=replay_counter,     # 和key 1 匹配, 用于匹配发送的每对消息，ap 每次重传它的包都会递增counter。
                        nonce=self.config.snonce,
                        wpa_key_length = 28,        # rsn_info 增加了group manag cipher suite
                        wpa_key=self.rsn_info)
        print("eapol_2_blank : ", bytes(eapol_2).hex())
        self.config.payload = bytes(eapol_2)

        calc_mic = Calc_MIC()
        self.config.ptk, self.config.mic = calc_mic.run(self.config)
        # print(self.config.mic)
        eapol_2[WPA_key].wpa_key_mic = bytes.fromhex(self.config.mic)

        eapol_2_packet = RadioTap() / Dot11(
                                type=2,
                                subtype=8,
                                FCfield=1,
                                addr1=self.config.mac_ap,
                                addr2=self.config.mac_sta,
                                addr3=self.config.mac_ap,
                                SC=32 )  / Dot11QoS() / LLC() / SNAP() / eapol_2
        # eapol_2_packet.show()
        conf.use_pcap = True
        sendp(eapol_2_packet, iface = self.config.iface)

        # Key (Message 3 of 4)
        logging.debug("\n-------------------------Key (Message 3 of 4): ")

        result = sniff(iface=self.config.iface,
                         lfilter=lambda r: (r.haslayer(EAPOL) and (r.getlayer(WPA_key).key_info  == 0x13c8 )) ,
                         store=1, count=1,
                         timeout=1)

        if len(result) > 0:
            print("成功捕获到 EAPOl Message 3 of 4")
        else:
            print("未成功捕获到符合条件的 EAPOL Message 3 of 4 ")
            sys.exit(1)
        eapol_3_packet = result[-1]
        # eapol_3_sequence = eapol_3_packet.payload.SC
        self.config.encrypt_msg = eapol_3_packet[WPA_key].wpa_key
        replay_counter = eapol_3_packet[WPA_key].replay_counter
        print("Encrypt Msg : ", self.config.encrypt_msg.hex())

        # 解密出 gtk , 需要修改
        # try:
        #     gtk_decrypt = GTKDecrypt(self.config)
        #     gtk , tk = gtk_decrypt.get_gtk()
        #     print("GTK : ", gtk)
        #     print("TK : ", tk)
        # except:
        #     print("GTK 计算异常")


        # Key (Message 4 of 4)
        print("\n-------------------------\nKey (Message 4 of 4): ")
        eapol_4 = EAPOL(version=1,
                        type=3,
                        len =95) / WPA_key(descriptor_type=2,
                                    key_info=0x0308,
                                    replay_counter = replay_counter # 和key 3 匹配, 用于匹配发送的每对消息。
                                    )
        self.config.payload = bytes(eapol_4)
        calc_mic2 = Calc_MIC()
        ptk, MIC_2 = calc_mic2.run(self.config)
        # print(self.config.payload.hex())
        # print(MIC_2)
        eapol_4[WPA_key].wpa_key_mic = bytes.fromhex(MIC_2)
        eapol_4_packet = RadioTap() / Dot11(
            type=2,
            subtype=8,
            FCfield=1,
            addr1=self.config.mac_ap,
            addr2=self.config.mac_sta,
            addr3=self.config.mac_ap,
            SC=48)  / Dot11QoS() / LLC() / SNAP() / eapol_4
        # eapol_4_packet.show()
        sendp(eapol_4_packet, iface = self.config.iface)

        return self.config.ptk



# ----------------------- Fuzzing/Testing ---------------------------------
def test(
    iface = "monwlan0",
    ssid = "testnetwork",
    psk = "passphrase",
    ap_mac = "e4:02:9b:5c:fe:fe",
    sta_mac = "00:c0:aa:00:09:3a",
    scene = 2,
):
    conf.iface = iface
    sae = SAEHandshake(password=psk,srcaddr=sta_mac,dstaddr=ap_mac)

    sae_commit_1 = sae.send_commit()
    t1 = AsyncSniffer(iface=iface, 
                      lfilter=lambda x: x[Dot11].addr1==sta_mac and x.haslayer(Dot11Auth) and x.getlayer(Dot11Auth).seqnum == 1, 
                      prn=lambda r: print(r.summary())
                      )
    t1.start()
    time.sleep(0.2)
    sendp(RadioTap() / sae_commit_1 ,iface=iface)
    # time.sleep(0.5)
    
    sae_commit_2 = t1.stop()[0]
    
    dot11_sae = SAE(sae_commit_2[Dot11Auth].payload.original)
    # dot11_sae.show()
    kck, pmk = sae.process_commit(dot11_sae)
    print("KCK", kck.hex())
    print("PMK", pmk.hex())
    sae.send_confirm(iface=iface)
    if scene == 0:
        sys.exit(0)

    rsn = RSN()
    rsn_info = rsn.get_rsn_info()
    packet = Dot11(
                addr1=ap_mac,
                addr2=sta_mac,
                addr3=ap_mac,
                SC=16)
    packet /= Dot11AssoReq(
                            cap='short-slot+ESS+privacy',
                            listen_interval=0x0001)
    packet /= Dot11Elt(ID=0, info="{}".format(ssid))
    packet /=  rsn_info
    # rate = bytes.fromhex("010882848b960c121824")
    rate = Dot11EltRates()
    packet /= rate
    assocation_1 = RadioTap() / packet

    # sniff 关联响应 association response
    # t1 = AsyncSniffer(iface=config.iface, lfilter=lambda x: x[Dot11].addr1==config.mac_sta and x.getlayer(Dot11AssoResp).seqnum == 1)
    # t1.start()
    # time.sleep(0.2)
    sendp(assocation_1, iface=iface)
    if scene == 1:
        sys.exit(0)
    # time.sleep(0.1)
    # result = t1.stop()[0]

    # 密钥协商
    config = WiFi_Object(
            iface = iface,
            ssid = ssid,
            psk = psk,
            mac_ap = ap_mac,
            mac_sta = sta_mac,
            anonce = "",
            snonce = "",
            payload = (""),
            kck = kck,
            pmk = pmk
        )


    EAPOL_connect = eapol_handshake(DUT_Object=config, rsn_info=rsn_info)
    PTK = EAPOL_connect.run()

    # 断开认证
    print("\n-------------------------\n从AP离开: ")
    TK : bytes = PTK[-16:]
    Plain_text = bytes(Dot11Deauth(reason=3))
    # print("TK & Plain_text : ", TK.hex(), Plain_text.hex())
    dot11_packet = ( 
                    Dot11(type=0, subtype=12, FCfield="protected",
                         addr1=config.mac_ap, 
                         addr2=config.mac_sta, 
                         addr3=config.mac_ap
                         ) / 
                    Dot11CCMP(ext_iv=1, PN0=4))
    # print("Dot11 Layer", bytes(dot11_packet).hex())
    packet = dot11_packet
    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(packet.PN5,packet.PN4,packet.PN3,packet.PN2,packet.PN1,packet.PN0)
    Nonce = CCMPCrypto.ccmp_get_nonce(priority='10', addr=config.mac_sta,pn=PN)
    cipher = AES.new(TK, AES.MODE_CCM, Nonce, mac_len = 8)
    deauth_cipher = cipher.encrypt(Plain_text)
    # print("deauth_cipher : ", deauth_cipher.hex())
    aad = CCMPCrypto.ccmp_get_aad(dot11_packet, amsdu_spp=False)
    MIC = CCMPCrypto.cbc_mac(TK, Plain_text, aad, Nonce)
    # print("Deauth MIC : ", MIC.hex())
    wpa3_deauth = ( 
                    RadioTap() / 
                    dot11_packet / 
                    Raw(deauth_cipher) / 
                    Raw(MIC)
                    )
    sendp(wpa3_deauth, iface = config.iface)


if __name__ == "__main__":
    test()