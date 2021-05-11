#Copyright (C) 1989, 1991 Free Software Foundation.
#SRATA MOHAMMED

from scapy.all import Ether, ARP, srp, sniff
import pickle
import time

#variable
attaques=[]
clients=[]
#les fonctions
def get_mac(ip):
    """trouver l'adresse mac par ip"""
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc
def supprimer(clients,attaques):
    """supprimer attaqueur dans la liste client"""
    trouver=0
    ligne=0
    #la recherche
    for client in clients:
        for attaque in attaques:
            if attaque['mac'] == client['mac']:
                trouver = 1
                break
            ligne+= 1
    #supprimer
    if trouver != 0:
        del clients[ligne]
def enterAtt(attaques,macAtt):
    """enter les mac """
    nbrfois=0
    for attaque in attaques:
        if attaque['mac'] == macAtt:
            nbrfois += 1
    if (nbrfois == 0) :
        attaques.append({ 'mac': macAtt})
def enterClient(clients,ipClient,macClient,pdst):
    """enter les ip et les mac """
    target_ip = '192.168.1.1'
    nbrfois=0
    if (ipClient != target_ip) and (pdst != target_ip) and (pdst != ipClient):
        for client in clients:
            if client['ip'] == ipClient:
                client['nbr'] += 1
                nbrfois+= 1
        if (nbrfois== 0) :
            clients.append({'ip':ipClient, 'mac': macClient, 'nbr':1})
def transfer(clients,attaques):
    """transfere de l'attaqueur dans les clients à les attaques"""
    trouver=0
    for client in clients:
        if client['nbr'] >=20:
            attaques.append({'mac': client['mac']})
            #supprimer
            del clients[trouver]
        trouver+=1
def saveData (clients,attaques):
    #enregistrer le fichier dans le dossier .idea sous le nom attaques
    # wb signifie l'ecriture
    pickle.dump(attaques, open(".idea/attaques.dat", "wb"))
    # enregistrer le fichier dans le dossier .idea sous le nom clients
    pickle.dump(clients, open(".idea/clients.dat", "wb"))
def process(packet):
    #reponse
    if packet[ARP].op == 2:
        try:
            real_mac = get_mac(packet[ARP].psrc)
            response_mac = packet[ARP].hwsrc
            if real_mac != response_mac:
                print(f"[!] Vous ete attaque par , REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
                enterAtt(attaques,response_mac)
            else:
                print( f"Request: {packet[ARP].psrc} and {packet[ARP].hwsrc} :repond a : {packet[ARP].pdst} and {packet[ARP].hwdst}")
                enterClient(clients,packet[ARP].psrc,real_mac,packet[ARP].pdst)
        except IndexError:
            # impossible de trouver le vrai mac
            # peut etre une fausse adresse IP ou un pare-feu bloque les paquets
            pass
    #question
    if packet[ARP].op == 1:
        try:
            real_mac = get_mac(packet[ARP].psrc)
            print(f"Request: {packet[ARP].psrc} et {packet[ARP].hwsrc} :pose la quetion a : {packet[ARP].pdst}  ?")
            enterClient(clients, packet[ARP].psrc, real_mac, packet[ARP].pdst)

        except IndexError:
            # impossible de trouver le vrai mac
            # peut etre une fausse adresse IP ou un pare-feu bloque les paquets
            pass
def scan():
    try:
        print("Debut")
        sniff(prn=process, filter="arp", store=0, timeout=120)
        supprimer(clients, attaques)
        transfer(clients, attaques)
        print("client:")
        # afficher client
        for client in clients:
            print(client['ip'], client['mac'], client['nbr'])
        print("attaque:")
        #afficher les adresse MAC de l'attaqueur
        for attaque in attaques:
            print(attaque['mac'])
        saveData(clients, attaques)
    except IndexError:
        pass
def redemarer(clients,attaques):
    c = 0
    b = 0
    for client in clients:
        c += 1
    for i in range(c):
        #supprimer
        del clients[i]
    for attaque in attaques:
        b += 1
    for i in range(b):
        # supprimer
        del attaques[i]



#programme
if __name__ == "__main__":
    while True:
        debut=time.time()
        while True:
            fin=time.time()
            scan()
            duree=(fin-debut)
            #duree 24 h en seconde 86400
            if(duree>=86400):
                #redemarrer au nouveau
                redemarer(clients,attaques)
                saveData(clients,attaques)
                break