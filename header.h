#pragma once
#include <stdlib.h>
#include <arpa/inet.h>
#include <string>
#include<iostream>
#include "mac.h"
#define FIXEDHSIZE 12
using namespace std;
#pragma pack(push, 1)
typedef struct radiotap_header {
        uint8_t        revesion;
        uint8_t        pad;
        uint16_t       length;
        uint32_t       present_flags;
        uint8_t        flags;
        uint8_t        data_Rate;
        uint16_t       channel_frequency;
        uint16_t       channel_flags;
        uint8_t        antenna_signal;
        uint8_t        antenna;
        uint16_t       RX_flags;
#define RTHSIZE 18
}radiotap_header;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct ieee_header {
        uint8_t        type_subtype; 
#define BEACON 0x80
#define PROBE 0x50
        uint8_t        flags;
        uint16_t       duration;
        Mac            dstmac;
        Mac       	   srcmac;
        Mac      	   BSSID;
        uint16_t       fragment_sequence;
#define IEHSIZE 24
}ieee_header;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct ssid_header{
        uint8_t        tagnum;
        uint8_t        taglength;
#define SSIDHSIZE 2
}ssid_header;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct pcktinfo{
        int PWR;
        int Beacons;
        string ESSID;
}pcktinfo;
#pragma pack(pop)