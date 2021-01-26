#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <iostream>
#include<string>
#include<set>
#include <unordered_map>
#include "header.h"
#include "mac.h"
using namespace std;
#define ETH_SIZE 14

unordered_map<Mac, pcktinfo> beaconMap;
unordered_map<Mac, pcktinfo> probeMap;
set<Mac> bKeys;
set<Mac> pKeys;
void insert(Mac key, uint8_t pwr, string essid, uint8_t type){
    auto pos=probeMap.end();
    pcktinfo newpcktinfo={0,};
    switch (type)
    {
    case PROBE:
        pKeys.insert(key);
        pos=probeMap.find(key);
        if(pos==probeMap.end()){
            probeMap[key]=newpcktinfo;
        }
        probeMap[key].Beacons++;
        probeMap[key].PWR=pwr;
        probeMap[key].ESSID=essid;
        break;
    case BEACON:
        bKeys.insert(key);
        pos=beaconMap.find(key);
        if(pos==beaconMap.end()){
            beaconMap[key]=newpcktinfo;
        }
        beaconMap[key].Beacons++;
        beaconMap[key].PWR=pwr;
        beaconMap[key].ESSID=essid;
        break;
    }
}
void display(){
    system("clear");
    printf("==============================Beacon==============================\n");
    printf("BSSID \t\t\t\tPWR   BEACONS\tESSID\n");
    for (auto iter = bKeys.begin(); iter != bKeys.end(); ++iter){
        Mac tempkey=(Mac)(*iter);
        pcktinfo temppcktinfo=beaconMap[tempkey];
        cout<<string(tempkey)<<"\t\t"<<temppcktinfo.PWR-256<<"\t"<<temppcktinfo.Beacons<<"\t"<<temppcktinfo.ESSID<<endl;
    }
    printf("\n\n==============================Probe==============================\n");
    printf("BSSID \t\t\t\tPWR   BEACONS\tESSID\n");
    for (auto iter = pKeys.begin(); iter != pKeys.end(); ++iter){
        Mac tempkey=(Mac)(*iter);
        pcktinfo temppcktinfo=probeMap[tempkey];
        cout<<string(tempkey)<<"\t\t"<<temppcktinfo.PWR-256<<"\t"<<temppcktinfo.Beacons<<"\t"<<temppcktinfo.ESSID<<endl;
    }
}
void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan1\n");
}
void show_pckt_info(pcap_t* handle){
    struct pcap_pkthdr* header;
    const u_char* packet;
    u_int size_ip,size_tcp,size_payload; //size of the headers and payload
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) return;
    if (res == -1 || res == -2) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(1);
    }
    radiotap_header* rt_header=(radiotap_header*)packet;
    ieee_header* i_header=(ieee_header*)(packet+RTHSIZE);
    if(i_header->type_subtype!=PROBE && i_header->type_subtype!=BEACON)
        return;
    ssid_header* s_header=(ssid_header*)(packet+RTHSIZE+IEHSIZE+FIXEDHSIZE);
    uint8_t ssidlen=s_header->taglength;
    char* essid=(char*)malloc(sizeof(char)*(ssidlen+1));
    char* essidtarget=(char*)(packet+RTHSIZE+IEHSIZE+FIXEDHSIZE+SSIDHSIZE);
    memcpy(essid,essidtarget,sizeof(char) * ssidlen);
    essid[ssidlen]=0;
    if(string(essid)=="")
        return;
    insert(i_header->BSSID,rt_header->antenna_signal-256,essid,i_header->type_subtype);
    display();
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    while (true) {
        show_pckt_info(handle);
    }
    pcap_close(handle);
}
