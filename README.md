# ITCchallenge penetration test
# TEAM 3
# Security
# date23/03/2025 15H:40
# name: Oumarou Azahidou Mahamadou


1
  Credentials exposés via FTP/HTTP : Youcef Sahraoui (123456789), Admin (ftp2025), etc.  
 Attaques détectées : DNS malformé (Opcode 12), tentative de brute-force SSH.  
Fuite de données critique : Fichier accounts.txt transféré via FTP. 

2 
  Exposure des donnees FTP:
USER admin  
PASS ftp2025  
STOR accounts.txt  
        Quies une tres grande fuite des données utilisateurs car les mots de passes son en clair(non cryptés)

  fuite de credential HTTP
ou on remarque des requetes interceptées:
        POST /login HTTP/1.1  
Host: target.com  
User=youcef.sahraoui&Pass=pass123 
ce qui nous a aythoriser à passer une session hijacking via burpsuite


  des packets DNS mal formés
    on a "Unknown operation (12)" vers 8.8.8.8

    qui techniquement veut dire:
    opcode: 12 qui peut etre exfiltree
    Transaction id: ox5175 qu'on a decodé avec python3



    Attack Atempts identifiée

 DNs queries identifiés
 Domaine	        Source IP	      Timestamp Fréquence Risque Associé
www.youtube.com	    192.168.1.30	  0.002146	    5x    Bandwidth abuse
www.facebook.com	192.168.82.86	  0.001984	3x	      Social Engineering (comme avec araoubia qui je peux tracker et manipuler et receuilr des infos ou oussama daouci etc.....)
www.wikipedia.org	192.168.241.11	  0.002304	2x	      Low risk  

Données critique 
     phone number 456123789 

MITM atack (man in the middle) en passan par l'attaque SYN (DOS) que j' ai essayé qui est le suivant en c:

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <pcap.h>
#include <thc-ipv4.h>
void help(char* itc_challenge){
    printf("%s %s (c) 2025 by %s %s, itc_challenge, 01, azcbs, RESOURCE);
    printf("Syntax: %s [ -i microseconds ] interface victim-ip [multicas-network-address]\n\n", itc-challenge);
    printf("Smurf the target with icmp echo replies. Target of echo request is the\n");
    printf("local all-nodes multicast address if not specified\n");
    // printf("Use -r to -use mode. \n\n");
    exit(-1);

}
int main(int argc, char *argv[]){
    unsigned char *pkt = NULL, buf[16], fakemac[7] = "\x00\x00\xde\xad\xbe\xef\";
    unsigned char *multicast6, *victim6;
    int i, pkt_len = 0, msec = 0;
    char *interface;
    int rawmode = 0;
}


SSH brute-force Evidence
pattern detecté:
   Multiples connexions SSH depuis 192.168.1.39 vers différents ports.

Utilisation de mots de passe faibles par l'admin (secureSSH!).

 DNS Tunneling suspicion
   Des flux dns malformed
      Nombre de paquets DNS anormaux : 20  
 Serveur cible : 8.8.8.8 (Possible C2 déguisé). 


     Données sensibles extrait


Utilisateur	     Mot de passe	Source
Youcef Sahraoui	 123456789	     FTP
Admin	         ftp2025	     FTP
Yousra Araoubia	 ramadan2025	 DNS



     0x5175==JBOO qui est le cle de chiffrement xor

      recommadations
        Isoler les serveurs FTP/SSH exposés.

Auditer les logs d'accès de l'utilisateur admin.

Vulnérabilité solution                    Outil recommandé
FTP non sécurisé	Migrer vers SFTP/SCP	       vsftpd + SSL
DNS malformé	Bloquer les requêtes non standard	 Snort Rule




