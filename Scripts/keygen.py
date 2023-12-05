import numpy, bitarray, os
import base64, random
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

#--- Take a 10-base number and return a 64-base number
def enBase64(num):
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    return base64.b64encode(num_bytes)

def writePubKey(f):
    f.write("-----BEGIN PUBLIC KEY-----\n")
    f.write
if __name__ == '__main__':
    #--- (p,q) : Different Primary Numbers 
    print("_________________________________________________________\n>>>> 2: Créer un couple de clés publique / privée <<<<")
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
    #--- Public Key : (e,n)
    pubKey_10 = int(str(n)+str(e))
    #print("+ La clé publique en base 10: "+str(pubKey_10))
    pubKey_16 = hex(pubKey_10)[2:]
    #print("+ La clé publique en base 16: "+str(pubKey_16))
    pubKey_64 = enBase64(int(str(n)+str(e))).decode('utf-8')
    #print("+ La clé publique en base 64: "+str(pubKey_64))
    test = input("+ Dans quel format voulez vous sauvegarder vos clés (1) DER (2) PEM : ")
    while int(test) != 1 and int(test) != 2:
        test = input("+ Erreur: La valeur saisie est incorrecte\n+ Dans quel format voulez vous sauvegarder vos clés (1) DER (2) PEM : ")
    fPubKey.write("-----BEGIN PUBLIC KEY-----\n")
    if int(test)==1:
        print("+ Vous avez choisi de sauvegarder vos clés en format DER.")
        fPubKey.write(str(pubKey_16))
    else:
        print("+ Vous avez choisi de sauvegarder vos clés en format PEM.")
        fPubKey.write(str(pubKey_64))
    fPubKey.write("\n-----END PUBLIC KEY-----")

    #--- Private Key : (d,n)
    priKey_10 = int(str(n)+str(d))
    #print("+ La clé privée en base 10: "+str(priKey_10))
    priKey_16 = hex(priKey_10)[2:]
    #print("+ La clé privée en base 16: "+str(priKey_16))
    priKey_64 = enBase64(int(str(n)+str(e))).decode('utf-8')
    #print("+ La clé privée en base 64: "+str(priKey_64))
    fPriKey.write("-----BEGIN PRIVATE KEY-----\n")
    if int(test)==1:
        fPriKey.write(str(priKey_16))
    else:
        fPriKey.write(str(priKey_64))
    fPriKey.write("\n-----END PRIVATE KEY-----")
    print("+ Les clés ont été générées avec succés.\n+ Fin du programme.")
    print("_________________________________________________________")

