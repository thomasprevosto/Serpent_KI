import random
from Scripts.utils import *

#''' v2 du Script
#''' Fonctionnel
#--- TEST of "petit théorème de Fermat" if number is primary
PATH_KEY = "Serpent_KI/Resources/key/"
def isProbablyPrimary(N):
    """
    Function isProbablyPrimary
    N: Nombre que l'on test pour savoir si c'est un nombre (probablement) premier
    Test : Si a^(N-1) ≡ 1 mod N, alors N est probablement premier
    """
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
    """
    Function generatePrimary1024
        Generate random (probably) primary number 
    """
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
def invertMod(aModulo, bNombre):
    """
    Function: invertMod
        Calcul de l'inverse modulaire en utilisant l'Algorithme d'Euclide étendu
        aModulo: Module
        bModulo: Nombre dont on cherche à obtenir l'inverse 
    """
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
    """
    Function: writePubKey
        Text Parsing Function
    """
    f.write("-----BEGIN PUBLIC KEY-----\n")
    f.write

def generateRSA():
    """
    Function: generateRSA
        Generate a pair of RSA keys
    """
    nameKey = input("+ Enter the name of the pair of keys : ")
    fPubKey = open(PATH_KEY+nameKey+"_public.key","w")
    fPriKey = open(PATH_KEY+nameKey+"_private.key","w")
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
    #--- d : Pow of deciphering -->  d ≡ e^(-1) mod φ(n)
    d= invertMod(phiN, e)
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

# Asymmetric encryption function using RSA keys
def cipherRSA():
    print("+ Starting asymmetric encryption using RSA keys")
    path = input("+ Please enter the path of your public key: ")
    e, n = getElementsFromKey(path)
    txt = input("+ Enter your message: ")
    txt_number = stringToInt(txt)
    cipher_txt = pow(txt_number, e, n)
    print(str(cipher_txt))

def decipherRSA():
    print("+ Starting asymmetric decryption using RSA keys")
    path = input("+ Please enter the path of your private key: ")
    d, n = getElementsFromKey(path)
    cipher_txt = int(input("+ Enter the encrypted message: "))
    txt = pow(cipher_txt, d, n)
    print(intToString(txt))


if __name__ == '__main__':
    print("_________________________________________________________\n>>>> 2: Create a Public/Private Key Pair <<<<")
    choice = input("+ Welcome to the RSA key generation space\n+ Do you want to generate a RSA key pair (1), encrypt a message (2), decrypt a message (3): ")
    while choice != "1" and choice != "2" and choice != "3":
        print("+ ERROR: incorrect entry!\n+ Usage: 1-Key Generation, 2-Message Encryption, 3-Message Decryption")
        choice = input("+ Do you want to generate a RSA key pair (1), encrypt a message (2), decrypt a message (3): ")
    if choice == "1":
        generateRSA()
        print("+ The keys have been successfully generated.\n+ End of the program.")
        print("_________________________________________________________")
    elif choice == "2":
        cipherRSA()
        print("+ End of the program.")
        print("_________________________________________________________")
    elif choice == "3":
        decipherRSA()
        print("+ End of the program.")
        print("_________________________________________________________")


