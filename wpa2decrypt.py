import hashlib
import binascii
import hmac
import binascii
from Crypto.Cipher import AES # pip install pycrypto pycryptodome pycryptodomex
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

passphrase = "smyl2021x7s3"
SSID = "shuimuyulin"
ssid_bytes = SSID.encode()

psk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid_bytes, 4096, 32)
psk_hex = binascii.hexlify(psk).decode()
print("PSK :", psk_hex)

pmk = psk

def prf_80211i(K, A, B, Len):
    R = b""
    i = 0
    while i <= ((Len + 159) / 160):
        hmac_result = hmac.new(K, A + bytes.fromhex("00") + B + bytes([i]), hashlib.sha1).digest()
        i += 1
        R += hmac_result
    return binascii.hexlify(R).decode()[:128]

def generate_ptk(pmk, anonce, snonce, AP_Addr, STA_Addr):
    ptk = prf_80211i(pmk, b"Pairwise key expansion", min(AP_Addr, STA_Addr) + max(AP_Addr, STA_Addr) + min(anonce, snonce) + max(anonce, snonce), 384)

    kck = ptk[:32]
    kek = ptk[32:64]
    tk = ptk[64:96]
    mic_tx = ptk[96:112]
    mic_rx = ptk[112:]

    return ptk, kck, kek, tk, mic_tx, mic_rx

anonce = bytes.fromhex("51fb8bd4b51261357fc9f34558825d74908f02c6e00c544a155894e37d438937")
snonce = bytes.fromhex("f9de2c53852db866acc6d7ad042bc580b64a323af6fc155b84ecd1f1d7dc25d8")
ap_mac = bytes.fromhex("58:41:20:fd:26:ed".replace(":",""))
client_mac = bytes.fromhex("00:1d:43:20:19:2d".replace(":",""))

ptk, kck, kek, tk, mic_tx, mic_rx = generate_ptk(pmk, anonce, snonce, ap_mac, client_mac)
print("Generated PTK :", kck, kek, tk, mic_tx, mic_rx)


def generate_gtk(kek, key_wrap_data):
    decrypt_key_wrap_data = aes_key_unwrap(bytes.fromhex(kek), bytes.fromhex(key_wrap_data))
    decrypt_key_wrap_data = binascii.hexlify(decrypt_key_wrap_data).decode()
    return decrypt_key_wrap_data[60:-4]

key_wrap_data = "0f77bb3d31d4da44391f7ce932da97839770566ea1ef357fb0ddae59c97376fcd8068ed372642cffabab45cc8a9433c9a705d0ade0501e23"
gtk = generate_gtk(kek, key_wrap_data)
print("GTK :", gtk)


# ccmp 메시지 복호화
qos_data_frame = bytes.fromhex("0f77bb3d31d4da44391f7ce932da97839770566ea1ef357fb0ddae59c97376fcd8068ed372642cffabab45cc8a9433c9a705d0ade0501e23")

def decrypt_data(tk, qos_data_frame):
    ccmp_key = bytes.fromhex(tk)
    priority = bytes.fromhex("00")
    ccmp_iv = bytes.fromhex("0000000001AE")
    nonce = priority + client_mac + ccmp_iv

    cipher = AES.new(ccmp_key, AES.MODE_CCM, nonce, mac_len=8)
    return cipher.decrypt(qos_data_frame)

plaintext = decrypt_data(tk, qos_data_frame)
print(plaintext.decode(errors='replace'))