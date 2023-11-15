# 配置网卡
 1. 挂载usb网卡 (虚拟机->可移动设备->ralink 802.11 n WLAN)
 2. 配置网卡为monitor模式
    ```sh
    airmon-ng                   # 显示存在一个可用wifi设备
    airmon-ng start wlan0     # 设置wifi网卡进入monitor模式,网卡名称变为wlan0mon
    ```
 3. 测试是否支持注入        
  ```aireplay-ng -9 wlan0mon```
 4. 扫描周围Wi-Fi网络       
  ```airodump-ng wlan0mon```
  ![Alt text](images/Readme/image-1.png)
 5. 配置网卡和网络频段一致，如网络显示为 Channel 10     
  ```airmon-ng start wlan0mon 10```

# 启动链路认证和关联测试
```python3 wifi_pharse1.py```

启动后将连接到wifi ztkj     

![Alt text](<images/Readme/image.png>)      

抓包截图        
![Alt text](images/Readme/1699872688929.png)


    ```sh
    └─# /bin/python /code/contrib/wifi/wifi_connect.py

    Scanning max 5 seconds for Authentication from BSSID 20:6b:e7:a3:fc:a0
    .
    # 发送认证请求
    Sent 1 packets.
    # 接收认证响应
    Detected Authentication from Source 20:6b:e7:a3:fc:a0
    STA is authenticated to the AP!

    (省略部分输出)

    Scanning max 5 seconds for Association Response from BSSID 20:6b:e7:a3:fc:a0
    .
    # 发送关联请求
    Sent 1 packets.
    # 接收到关联响应
    Detected Association Response from Source 20:6b:e7:a3:fc:a0
    STA is connected to the AP!
    ```

# 运行4次EAPOL协议，协商通信密钥
    仅完成算法部分，未加入报文通信流程  -- 2023-11-15 17:12:49      
    ```python3  wifi_pharse2.py```


# 如何排查网卡注入问题和其他
>Wi-Fi 帧注入的正确性 - XWiki   
>https://wiki.dev.shuimuyulin.com/xwiki/bin/view/Main/xfuzz-protocol/WIFI%20FUZZ/Wi-Fi%20%E5%B8%A7%E6%B3%A8%E5%85%A5%E7%9A%84%E6%AD%A3%E7%A1%AE%E6%80%A7/