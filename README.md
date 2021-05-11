# PROTECTNETWORK

Chaque utilisateur du réseau essaie de se protéger contre les attaques en utilisant un logiciel de sécurité, mais parfois ce programme n'est pas efficace pour assurer cette protection, en plus d'être considéré comme une solution individuelle qui ne peut pas protéger les autres utilisateurs. Pour ces raisons, nous avons trouvé une solution d'actualité que nous avons appelée "PROTECTNETWORK" qui fournit une protection générale pour l'ensemble du réseau contre ces types d'attaques.

Étant donné que les solutions connues sont très coûteuses et très complexes, nous avons essayé dans notre travail de trouver une solution simple d'actualité qui dépend de la nécessité d'empêcher les pirates de se connecter à Internet, d'assurer la sécurité des autres utilisateurs et d'assurer leur connexion.

Nous avons appelé cette solution "PROTECT NETWORK", qui est un système de sécurité contre les attaques d'usurpation du routeur programmable en Python, qui effectue deux traitements différents, le premier est de détecter l'identité du pirate avec un scanner réseau, tandis que le second est de le séparer directement du réseau par un autre type d'attaque forte.

Selon l'étude de Netcut ,nous avons généralement conclu que toutes sortes de programmes qui nous permettent de mettre en œuvre des attaques d'usurpation de routeur, sont basées sur le même principe de fonctionnement que d'une part, nous avons constaté qu'au démarrage, ils envoient un grand nombre de paquets ARP requêtes pour analyser le réseau afin d'avoir l'identité de chaque utilisateur, en revanche, nous avons remarqué que lors de l'exécution de l'attaque, ils ont effectué une attaque d'empoisonnement ARP car ils envoient des paquets de réponse ARP incorrects contenant une adresse MAC qui ne correspond pas au routeur qui a une adresse IP "192.1681.1.1". 

Selon ces notes, dans la première partie de notre solution nous avons tenté de révéler l'identité des hackers du réseau par la mise en œuvre parallèle et périodique de deux méthodes différentes: 
   - La première consiste à compter le nombre de paquets ARP requis de chaque utilisateur envoyé dans le réseau. En analysant les paquets reçus, si le nombre de paquets d'un utilisateur dépasse un certain grand nombre (par exemple 20), donc il s'agit d'un pirate. Par contre, dans le cas normal, les utilisateurs envoient le paquet de commande très peu de fois car ils ne dépassent pas dix fois par heure. 
   - La deuxième est basé sur une comparaison de l'adresse MAC physique du routeur avec l'adresse MAC source des paquets de réponse ARP envoyés par l'adresse IP "192.168.1.1". Si le paquet de réponse ARP contient une adresse MAC source différente de l'adresse MAC du routeur, alors ce paquet est le paquet d'empoisonnement ARP émis par un pirate identifié par l'adresse MAC source de cette paquet. 
   
Après avoir identifié les pirates dans la première partie, nous sommes passés à les séparer d'Internet à l'aide d'un type d'attaque qui ne permet pas l'authentification. 

L'authentification réseau est utilisée pour authentifier une machine lorsqu'elle essaie de se connecter au réseau pour lui permettre d'utiliser le réseau ou non. Au cours de cette étape, l'appareil dispose des autorisations nécessaires auprès du serveur selon le mécanisme de fonctionnement du TCP (Transmission Control Protocol) qui fournit les services attendus de la couche transport dans le modèle OSI en gérant la fragmentation et le réassemblage en paquets des segments de données qui transitent via le protocole IP.
