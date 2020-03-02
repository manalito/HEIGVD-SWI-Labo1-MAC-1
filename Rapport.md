# Sécurité des réseaux sans fil
> Laboratoire: Labo1-MAC-1   
> Étudiants: Yimnaing Crescence, Siu Aurélien


a) Utiliser la fonction de déauthentification de la suite aircrack, capturer les échanges et identifier le Reason code et son interpretation.

Client mac address: XiaomiCo_8c:63:71 (c4:0b:cb:8c:63:71)
AP mac address: AskeyCom_c4:10:a3 (b4:ee:b4:c4:10:a3)

Commande utilisée: 

```sh
sudo aireplay-ng -0 1 -a b4:ee:b4:c4:10:a3 -c c4:0b:cb:8c:63:71 mon0
```

Question : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

Reason code: Class 3 frame received from nonassociated STA (0x0007)



