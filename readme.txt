--------------------------------------------------------------------------------
---------------------------------- WireTurtle ----------------------------------
--------------------------------------------------------------------------------

Pour compiler le code :
'javac * .java'

Pour exécuter le programme :
WireTurtle [-f protocol_filter | -c conversation_number] file.pcap
  protocol_filter : ARP ICMP IP TCP UDP HTTP FTP DHCP DNS
  conversation_number : 0 pour toutes les conversations

Le nombre de conversation total est affiché à la fin de l'affichage (sauf si une
conversation spécifique est déjà sélectionnée).

Pour faciliter la lecture de gros fichiers PCAP il est conseiller de rajouter
un ' | less -r' pour paginer le résultat en conservant les codes couleurs.

--------------------------------------------------------------------------------
-------------------------- Modélisation couches OSI ----------------------------
--------------------------------------------------------------------------------

Chaque paquet inclut un attribut encapsulated_packet représentant le paquet
encapsulé, pour chaque protocole le type de cet attribut correspond à une classe
abstraite représentant la couche supérieur du modèle OSI (en occultant les
couches 1, 5 et 6). Chaque classe de protocole étend donc ces classes LayerX.

--------------------------------------------------------------------------------
------------------------------ Conversation TCP --------------------------------
--------------------------------------------------------------------------------

Les conversations TCP sont détectés grâces aux paquets de handshake.
Les paquets du PCAP vont être parcourus à la recherche de la séquence
SYN - SYN/ACK - ACK, puis une conversation va être créé dont l'id sera la
concaténation de l'ip source du port source de l'ip destination et du port
destination par la suite tout paquet redonnant ce même id (ou l'id avec les
sources et destinations inversées) sera placé dans la conversation.
Une fois tous les paquets de la conversations récupérés, le contenu sera
concaténé avec des couleurs spécifiques pour chaque machine.
Et une tentative de reconnaissance du protocole sera effectuée par mot-clé afin
de détecté une conversation HTTP ou FTP. Si ces protocoles sont connus une
méthode sera appelé afin de bien construire les encapsulated_packet appropriés.


--------------------------------------------------------------------------------
------------------------ Reconnaissance protocolaire ---------------------------
--------------------------------------------------------------------------------

Dans TCP comme UDP afin de reconnaître le protocole encapsulé une tentative de
construction de paquet DNS est effectuée. Si celle ci échoue le paquets est
analysé pour vérifié s'il contient le magic cookie du DHCP. Si aucun de ces deux
protocoles n'est trouvé alors la reconnaissance est basée sur le port source ou
destination habituels de HTTP ou FTP.
Si HTTP ou FTP communiquent sur d'autres port ces protocoles seront détectés
grâce à leur appartenance à une conversation dont l'attribut protocole
correspond.
Si aucun protocole n'est reconnu à la couche 4 les données restantes sont
affichés en ASCII (les ASCII visible, les tabulations et les sauts de lignes
uniquement).
