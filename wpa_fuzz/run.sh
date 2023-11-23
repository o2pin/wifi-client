# sudo airmon-ng start wlan0 6
# sudo iwconfig wlan0mon channel 6

sudo ~/.python3/bin/python3 wpa_fuzz/main.py wlan0mon --client-mac 00:1d:43:20:18:d4 --ssid shuimuyulin-guest --psk smyl2020 --ap-mac "5A:41:20:1D:26:ED"
# sudo ~/.python3/bin/python3 wpa_fuzz/main.py wlan0mon

