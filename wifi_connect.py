import multiprocessing
from scapy.all import *
 
from monitor_ifc import Monitor



class ConnectionPhase:
    """
    Establish a connection to the AP via the following commands
    """
 
    def __init__(self, monitor_ifc, sta_mac, bssid):
        self.state = "Not Connected"
        self.mon_ifc = monitor_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
 
    def send_authentication(self):
        """
        Send an Authentication Request and wait for the Authentication Response.
        Which works if the user defined Station MAC matches the one of the
        wlan ifc itself.
 
        :return: -
        """
        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid) / Dot11Auth(
                algo=0, seqnum=0x0001, status=0x0000)
 
        packet.show()
 
        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_auth,
            args=(result_queue, ))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet, ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Authenticated"
 
    def send_assoc_request(self, ssid):
        """
        Send an Association Request and wait for the Association Response.
        Which works if the user defined Station MAC matches the one of the
        wlan ifc itself.
 
        :param ssid: Name of the SSID (ESSID)
        :return: -
        """
        if self.state != "Authenticated":
            print("Wrong connection state for Association Request: {0} "
                  "- should be Authenticated".format(self.state))
            return 1
 
        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid) / Dot11AssoReq(
                cap=0x1100, listen_interval=0x00a) / Dot11Elt(
                    ID=0, info="{}".format(ssid))
        packet.show()
        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_assoc_resp,
            args=(result_queue,))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet, "AssoReq", ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Associated"



def main():
    SSID_smylguest = 'shuimuyulin-guest'    #Network name here
    SSID_ztkj = 'ztkj'    #Network name here
    SSID_direct2f = 'DIRECT-2F4DDFDF'    #Network name here
    iface = 'wlan0'         #Interface name here
    iface_mon = 'wlan0mon'         #Interface name here
    iface_at0 = 'at0'
    my_mac1 = "0e:d6:11:00:4e:10"      # kali RT3070 
    # my_mac2 = "9a:7a:8a:f1:cf:9b"      
    my_mac_mon = "00:a1:b0:79:03:f6"  
    smylguest_mac = "5A:41:20:1D:26:ED"        # shuimuyulin-guest
    ff_mac = "ff:ff:ff:ff:ff:ff"
    ztkj_mac = "20:6b:e7:a3:fc:a0"
    direct2f_mac = "DE:CD:2F:4D:5F:DF"
    
    #   addr1     =   (RA=DA)  目的地址
    #   addr2     =   (TA=SA)  源地址
    #   addr3     =   (BSSID/STA)   AP/Client  地址
    
    
    monitor_ifc = iface_mon
    sta_mac = my_mac_mon
    bssid = ztkj_mac        # 改 wifi ap mac地址
    conf.iface = monitor_ifc
 
    # mac configuration per command line arguments, MACs are converted to
    # always use lowercase
    mon_ifc = Monitor(monitor_ifc, sta_mac.lower(), bssid.lower())
 
    connection = ConnectionPhase(mon_ifc, sta_mac, bssid)
    connection.send_authentication()
    if connection.state == "Authenticated":
        print("STA is authenticated to the AP!")
    else:
        print("STA is NOT authenticated to the AP!")
    time.sleep(1)
    connection.send_assoc_request(ssid=SSID_ztkj)       # 改wifi名称
 
    if connection.state == "Associated":
        print("STA is connected to the AP!")
    else:
        print("STA is NOT connected to the AP!")
 
if __name__ == "__main__":
    sys.exit(main())