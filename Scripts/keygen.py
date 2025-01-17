import random
from utils import *
#''' v1 du Script
#''' Fonctionnel
#''' Améliorations potentielles :  Intégrer ASN.1 dans le format des clés pour plus de propreté.
#                                  Réecrire la fonction inverseModulaire.
#--- TEST of "petit théorème de Fermat" if number is primary
def isProbablyPrimary(N):
    k=5
    #--- k : nombre de tests
    #--- a un entier positif tel que a < N 
    #--- Test : Si a^(N-1) ≡ 1 mod N, alors N est probablement premier
    for i in range(k):
        a = random.randint(2, N - 1)
        if pow(a, N - 1, N) != 1:
            return False  # N est composé
    
    return True  # N est probablement premier

#--- GENERATE random primary number of 1024 bits
def generatePrimary1024():
    i=0
    while True:
        #--- GEN RANDOM 1024 Number
        num = random.getrandbits(1024)
        num |= (1 << 1024 - 1) | 1
        #--- Petit Fermat TEST
        if isProbablyPrimary(num):
            #print("+ "+str(i)+" itérations.")
            return num
        i += 1



#--- Fonction utilisant l'Algorithme d'Euclide étendu et qui permet de calculer l'inverse modulaire
def inverseModulaire(aModulo, bNombre):
    
    modulo = aModulo
    
    x = 0
    y = 1
    u = 1
    v = 0
    
    while bNombre != 0:
        q = aModulo // bNombre
        r = aModulo % bNombre
        
        m = x - u * q
        n = y - v * q
        
        aModulo = bNombre
        bNombre = r
        x = u
        y = v
        u = m
        v = n
        
    return x % modulo if aModulo == 1 else 0

def writePubKey(f):
    f.write("-----BEGIN PUBLIC KEY-----\n")
    f.write

def generateRSA():
    nameKey = input("+ Veuillez entrer le nom de la paire de clés : ")
    fPubKey = open(nameKey+"_public.key","w")
    fPriKey = open(nameKey+"_private.key","w")
    p = generatePrimary1024()
    q = generatePrimary1024()
    while p==q:
        q = generatePrimary1024
    #--- n = p*q
    n = p * q
    #print("+ n ="+str(n))
    #--- phi(n)
    phiN = (p-1) * (q-1)
    #print("+ phi(n)="+str(phiN))
    #--- e : Pow of ciphering // Pour l'instant e = 65537, dans un second temps on la calculera
    e = 65537
    #--- d : Pow of deciphering -->  d ≡ e^(-1) mod φ(n) || A refaire
    d= inverseModulaire(phiN, e)
    #print("+ d = "+str(d))
    #--- Verification
    #ver = d*e % phiN
    #if ver == 1:
    #    print("+ Une vérification a été effectué, d est bien l'inverse modulaire de e dans phi de N")
    #--- On test que les clés RSA fonctionnent correctement
    #testGeneration(d,e,n)
    #print("d="+str(d)+"\ne="+str(e)+"\nn="+str(n))
    #--- Public Key : (e,n)
    pubKey_10 = int(str(n)+str(e))
    strpubKey_10 = "n="+str(n)+"e="+str(e)
    #print("+ La clé publique en base 10: "+str(pubKey_10))
    pubKey_16 = hex(pubKey_10)[2:]
    #print("+ La clé publique en base 16: "+str(pubKey_16))
    #pubKey_64 = numToBase64(pubKey_10).decode('utf-8')
    strpubKey_64 = stringToBase64(strpubKey_10)
    #print("+ La clé publique en base 64: "+str(pubKey_64))
    fPubKey.write("-----BEGIN PUBLIC KEY-----\n")
    fPubKey.write(str(strpubKey_64))
    fPubKey.write("\n-----END PUBLIC KEY-----")
    #--- Private Key : (d,n)
    priKey_10 = int(str(n)+str(d))
    strpriKey_10 = "n="+str(n)+"d="+str(d)
    #print("+ La clé privée en base 10: "+str(priKey_10))
    priKey_16 = hex(priKey_10)[2:]
    #print("+ La clé privée en base 16: "+str(priKey_16))
    #priKey_64 = numToBase64(priKey_10).decode('utf-8')
    strpriKey_64 = stringToBase64(strpriKey_10)
    #print("+ La clé privée en base 64: "+str(priKey_64))
    fPriKey.write("-----BEGIN PRIVATE KEY-----\n")
    fPriKey.write(str(strpriKey_64))
    fPriKey.write("\n-----END PRIVATE KEY-----")
    return nameKey

#Fonction de chiffrement asymétrique à l'aide de clés RSA
def cipherRSA():
    print("+ Début du chiffrement asymétrique à l'aide de clés RSA")
    path=input("+ Veuillez entrer le chemin de votre clé publique: ")
    e,n = getElementsFromKey(path)
    txt = input("+ Saisir votre message: ")
    txt_number = stringToInt(txt)
    cipher_txt = pow(txt_number,e,n)
    print(str(cipher_txt))

def decipherRSA():
    print("+ Début du dechiffrement asymetrique à l'aide de clés RSA")
    path = input("+ Veuillez entrer le chemin de votre clé privée: ")
    d,n = getElementsFromKey(path)
    cipher_txt = int(input("+ Saisir le message chiffré: "))
    txt = pow(cipher_txt,d,n)
    print(intToString(txt))

if __name__ == '__main__':
    print("_________________________________________________________\n>>>> 2: Créer un couple de clés publique / privée <<<<")
    choice = input("+ Bienvenue dans l'espace de génération des clés RSA\n+ Voulez vous générer une paire de clés RSA (1), chiffrer un message (2), déchiffrer un message (3): ")
    while choice != "1" and choice != "2" and choice != "3":
        print("+ ERREUR: saisie incorrecte !\n+ Usage: 1-Generation de clés, 2-Chiffrement d'un message, 3-Dechiffrement d'un message")
        choice = input("+ Voulez vous générer une paire de clés RSA (1), chiffrer un message (2), déchiffrer un message (3): ")
    if choice == "1":
        generateRSA()
        print("+ Les clés ont été générées avec succés.\n+ Fin du programme.")
        print("_________________________________________________________")
    elif choice == "2":
        cipherRSA()
        print("+ Fin du programme.")
        print("_________________________________________________________")
    elif choice == "3":
        decipherRSA()
        print("+ Fin du programme.")
        print("_________________________________________________________")

