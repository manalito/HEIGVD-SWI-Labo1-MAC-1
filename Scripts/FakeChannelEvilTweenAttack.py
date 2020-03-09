#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors  : yimnaing Kamdem && Siu Aurelien
#  Objectif : Développer un script en Python/Scapy avec les fonctionnalités suivantes :
#				- Dresser une liste des SSID disponibles à proximité
#				- Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
#				- Permettre à l'utilisateur de choisir le réseau à attaquer
#				- Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant
#				    à 6 canaux de séparation du réseau original
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

from scapy.all import *
interface = "wlan0mon"
aps = {} # dictionary to store unique APs
aps_ssid = []
channels = []
powers = []
number=0

pkt = ""

def sniffing(packetToSniff):
    sniffing.counter = getattr(sniffing, 'counter', 0)
    if ( (packetToSniff.haslayer(Dot11Beacon))):
        # Dresser une liste des SSID disponibles à proximité       
        if packetToSniff.info not in aps_ssid :

            ssid       = packetToSniff[Dot11Elt].info
            aps_ssid.append(ssid)
            bssid      = packetToSniff[Dot11].addr3    
            channel    = int( ord(packetToSniff[Dot11Elt:3].info))
            power      = -(256 - ord(packetToSniff.notdecoded[-2:-1]))
    
            # Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances

            # Display discovered AP
            print('Number={0}, SSID= {1}, BSSID={2}, channel={3}, power={4} dBm.'\
                .format(sniffing.counter, ssid, bssid, int(channel), power ))
            
            sniffing.counter += 1

print('Liste des AP')
# On sniffe en passant en fonction de callback la fonction sniffing
sniff(count=100, iface=interface, prn=sniffing)


# Permettre à l'utilisateur de choisir le réseau à attaquer
if(aps_ssid) :
    number = int(input("Please choose the AP to attack (number): "))

else: print ('No AP detected')
  
  #Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant
    #à 6 canaux de séparation du réseau original
