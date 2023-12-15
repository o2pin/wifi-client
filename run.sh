# 设置监控模式
# sudo airmon-ng start wlan0 6

# 设置网卡channel保持ap一致
# sudo iwconfig wlan0mon channel 6

# 检查是否有其他服务使用无线网卡, 结束会影响wifi注入的服务
# sudo airmon-ng check
# sudo airmon-ng check kill

# 链路认证 密钥协商

sudo ~/.python3/bin/python3 main.py --iface wlan0mon --ssid shuimuyulin-guest --psk smyl2020 --ap-mac "5A:41:20:1D:26:ED"
sudo ~/project/wifi-framework/setup/venv/bin/python3 ./main.py --iface wlan1 --ssid testnetwork --psk passphrase --ap-mac 02:00:00:00:00:00 --scene 2 --suite WPA2
sudo ~/project/wifi-framework/setup/venv/bin/python3 ./main.py --iface wlan3 --ssid testnetwork --psk passphrase --ap-mac 02:00:00:00:02:00 --scene 2 --suite WPA3
