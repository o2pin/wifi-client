# 设置监控模式
# sudo airmon-ng start wlan0 6

# 设置网卡channel保持ap一致
# sudo iwconfig wlan0mon channel 6

# 检查是否有其他服务使用无线网卡, 结束会影响wifi注入的服务
# sudo airmon-ng check
# sudo airmon-ng check kill

# 链路认证 密钥协商
# sudo ~/.python3/bin/python3 wpa_fuzz/main.py wlan0mon --client-mac 00:1d:43:20:18:d4 --ssid shuimuyulin-guest --psk smyl2020 --ap-mac "5A:41:20:1D:26:ED"

sudo ~/.python3/bin/python3 ./main.py wlan0mon
