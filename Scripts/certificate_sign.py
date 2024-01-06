#CE SCRIPT comptient :  La génération des demandes de certificats (CSR) -- La génération des certificats -- La signature des certificats
#---Hash Input message
from Scripts.keygen import getElementsFromKey,parseRSA,generateRSA,stringToBase64,base64ToString
import os,datetime

#---------------------------------------------------------HASH
#---Translate Binary To Hexa
def b2Tob16(value):
  #takes list of 32 bits
  #convert to string
  value = ''.join([str(x) for x in value])
  #creat 4 bit chunks, and add bin-indicator
  binaries = []
  for d in range(0, len(value), 4):
    binaries.append('0b' + value[d:d+4])
  #transform to hexadecimal and remove hex-indicator
  hexes = ''
  for b in binaries:
    hexes += hex(int(b ,2))[2:]
  return hexes

#---Add Zeros to Input
def fillZeros(bits, length=8, endian='LE'):
    l = len(bits)
    if endian == 'LE':
        for i in range(l, length):
            bits.append(0)
    else: 
        while l < length:
            bits.insert(0, 0)
            l = len(bits)
    return bits

#--- Chunker
def chunker(bits, chunk_length=8):
    # divides list of bits into desired byte/word chunks, 
    # starting at LSB 
    chunked = []
    for b in range(0, len(bits), chunk_length):
        chunked.append(bits[b:b+chunk_length])
    return chunked

#--- Initialisation du message
def initializer(values):
    #convert from hex to python binary string (with cut bin indicator ('0b'))
    binaries = [bin(int(v, 16))[2:] for v in values]
    #convert from python string representation to a list of 32 bit lists
    words = []
    for binary in binaries:
        word = []
        for b in binary:
            word.append(int(b))
        words.append(fillZeros(word, 32, 'BE'))
    return words
#TEMPORAIRE : Translate
def translate(message):
    #string characters to unicode values
    charcodes = [ord(c) for c in message]
    #unicode values to 8-bit strings (removed binary indicator)
    bytes = []
    for char in charcodes:
        bytes.append(bin(char)[2:].zfill(8))
    #8-bit strings to list of bits as integers
    bits = []
    for byte in bytes:
        for bit in byte:
            bits.append(int(bit))
    return bits

#PreProcess
def preprocessMessage(message):
    # translate message into bits
    bits = translate(message)
    #message length 
    length = len(bits)
    # get length in bits  of message (64 bit block)
    message_len = [int(b) for b in bin(length)[2:].zfill(64)]
    #if length smaller than 448 handle block individually otherwise
    #if exactly 448 then add single 1 and add up to 1024 and if longer than 448
    #create multiple of 512 - 64 bits for the length at the end of the message (big endian)
    if length < 448:
        #append single 1
        bits.append(1)
        #fill zeros little endian wise
        bits = fillZeros(bits, 448, 'LE')
        #add the 64 bits representing the length of the message
        bits = bits + message_len
        #return as list
        return [bits]
    elif 448 <= length <= 512:
        bits.append(1)
        #moves to next message block - total length = 1024
        bits = fillZeros(bits, 1024, 'LE')
        #replace the last 64 bits of the multiple of 512 with the original message length
        bits[-64:] = message_len
        #returns it in 512 bit chunks
        return chunker(bits, 512)
    else:
        bits.append(1)
        # loop until multiple of 512 + 64 bit message_len if message length exceeds 448 bits
        while (len(bits)+64) % 512 != 0:
            bits.append(0)
        #add the 64 bits representing the length of the message    
        bits = bits + message_len
        #returns it in 512 bit chunks
        return chunker(bits, 512)

#--------------------------------------------------------------- SETS DE FONCTIONS
#truth condition is integer 1
def isTrue(x): return x == 1

#simple if 
def if_(i, y, z): return y if isTrue(i) else z

#and - both arguments need to be true
def and_(i, j): return if_(i, j, 0)
def AND(i, j): return [and_(ia, ja) for ia, ja in zip(i,j)] 

#simply negates argument
def not_(i): return if_(i, 0, 1)
def NOT(i): return [not_(x) for x in i]

#retrun true if either i or j is true but not both at the same time
def xor(i, j): return if_(i, not_(j), j)
def XOR(i, j): return [xor(ia, ja) for ia, ja in zip(i, j)]

#if number of truth values is odd then return true
def xorxor(i, j, l): return xor(i, xor(j, l))
def XORXOR(i, j, l): return [xorxor(ia, ja, la) for ia, ja, la, in zip(i, j, l)]

#get the majority of results, i.e., if 2 or more of three values are the same 
def maj(i,j,k): return max([i,j,], key=[i,j,k].count)
# rotate right
def rotr(x, n): return x[-n:] + x[:-n]
# shift right
def shr(x, n): return n * [0] + x[:-n]

#full binary adder
def add(i, j):
  #takes to lists of binaries and adds them
  length = len(i)
  sums = list(range(length))
  #initial input needs an carry over bit as 0
  c = 0
  for x in range(length-1,-1,-1):
    #add the inout bits with a double xor gate
    sums[x] = xorxor(i[x], j[x], c)
    #carry over bit is equal the most represented, e.g., output = 0,1,0 
    # then 0 is the carry over bit
    c = maj(i[x], j[x], c)
  #returns list of bits 
  return sums
#--------------------------------------------------------------------------------
def sha256(message): 
    
    #---Constantes
    h_hex = ['0x6a09e667', '0xbb67ae85', '0x3c6ef372', '0xa54ff53a', '0x510e527f', '0x9b05688c', '0x1f83d9ab', '0x5be0cd19']

    K = ['0x428a2f98', '0x71374491', '0xb5c0fbcf', '0xe9b5dba5', '0x3956c25b', '0x59f111f1', '0x923f82a4',
    '0xab1c5ed5', '0xd807aa98', '0x12835b01', '0x243185be', '0x550c7dc3', '0x72be5d74', '0x80deb1fe', 
    '0x9bdc06a7', '0xc19bf174', '0xe49b69c1', '0xefbe4786', '0x0fc19dc6', '0x240ca1cc', '0x2de92c6f', 
    '0x4a7484aa', '0x5cb0a9dc', '0x76f988da', '0x983e5152', '0xa831c66d', '0xb00327c8', '0xbf597fc7', 
    '0xc6e00bf3', '0xd5a79147', '0x06ca6351', '0x14292967', '0x27b70a85', '0x2e1b2138', '0x4d2c6dfc', 
    '0x53380d13', '0x650a7354', '0x766a0abb', '0x81c2c92e', '0x92722c85', '0xa2bfe8a1', '0xa81a664b', 
    '0xc24b8b70', '0xc76c51a3', '0xd192e819', '0xd6990624', '0xf40e3585', '0x106aa070', '0x19a4c116', 
    '0x1e376c08', '0x2748774c', '0x34b0bcb5', '0x391c0cb3', '0x4ed8aa4a', '0x5b9cca4f', '0x682e6ff3', 
    '0x748f82ee', '0x78a5636f', '0x84c87814', '0x8cc70208', '0x90befffa', '0xa4506ceb', '0xbef9a3f7', 
    '0xc67178f2']
    
    #---Initialisation des variables
    k = initializer(K)
    h0, h1, h2, h3, h4, h5, h6, h7 = initializer(h_hex)
    chunks = preprocessMessage(message)

    #---Operations de Hash
    for chunk in chunks:
        w = chunker(chunk, 32)
        for _ in range(48):
            w.append(32 * [0])
        for i in range(16, 64):
            s0 = XORXOR(rotr(w[i-15], 7), rotr(w[i-15], 18), shr(w[i-15], 3) ) 
            s1 = XORXOR(rotr(w[i-2], 17), rotr(w[i-2], 19), shr(w[i-2], 10))
            w[i] = add(add(add(w[i-16], s0), w[i-7]), s1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        for j in range(64):
            S1 = XORXOR(rotr(e, 6), rotr(e, 11), rotr(e, 25) )
            ch = XOR(AND(e, f), AND(NOT(e), g))
            temp1 = add(add(add(add(h, S1), ch), k[j]), w[j])
            S0 = XORXOR(rotr(a, 2), rotr(a, 13), rotr(a, 22))
            m = XORXOR(AND(a, b), AND(a, c), AND(b, c))
            temp2 = add(S0, m)
            h = g
            g = f
            f = e
            e = add(d, temp1)
            d = c
            c = b
            b = a
            a = add(temp1, temp2)
        h0 = add(h0, a)
        h1 = add(h1, b)
        h2 = add(h2, c)
        h3 = add(h3, d)
        h4 = add(h4, e)
        h5 = add(h5, f)
        h6 = add(h6, g)
        h7 = add(h7, h)
    digest = ''
    for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
        digest += b2Tob16(val)
    return digest


#-----------------------------------------------------------------------------------------END HASH
#-----------------------------------------------------------------------------------------FONCTIONS DE TRAITEMENTS
def parseCSR(cert):
    # Supprimer les lignes "-----BEGIN" et "-----END"
    cert_sans_en_tetes = '\n'.join(ligne for ligne in cert.split('\n') if not ligne.startswith('-----BEGIN') and not ligne.startswith('-----END'))
    return cert_sans_en_tetes

def changeField(champ_a_modifier,valeur_du_champ,text_cert):
    lignes = ""
    list = text_cert.split("\n")
    for ligne in list:
        if champ_a_modifier in ligne:
            lignes = lignes + ("\n\t\t\t"+champ_a_modifier+": "+valeur_du_champ)
        else:
            lignes = lignes + (ligne)+"\n"
    return lignes
#-----------------------------------------------------------------------------------------CERTIFICATS
#--- Fonction qui permet de demander les informations générales à l'utilisateur
def askUser():
    commonName = input("+ Nom commun (www.example.com CN): ")
    organization = input("+ Organisation (O): ")
    organization_unit = input("+ Unité d'organisation (OU): ")
    localization = input("+ Localisation (L): ")
    state = input("+ Etat ou Province (ST): ")
    pays = input("+ Pays (C): ")
    mail = input("+ Adresse Mail (@): ")
    resultString = "CN="+commonName+", ST="+state+", L="+localization+", O="+organization+", OU="+organization_unit+", C="+pays+", @="+mail
    return resultString


#--- Fonction qui permet de récupérer la signature du demandeur de certificat 
#-   La signature correspond au hash de la clé privée de l'utilisateur.
#-   Amélioration : convertir le hash en bytes et en hexa
def getPrivateSignature():
    hasCert = input("+ Avez vous une paire de clés RSA ? (O) ou (N) : ")
    while hasCert != "O" and hasCert != "N":
        print("+ ERREUR : saisie incorrecte\n+ USAGE: O-oui N-non")
        hasCert = input("+ Avez vous une paire de clés RSA ? (O) ou (N) : ")
    if hasCert == "O":
        #---Si l'utilisateur possede une paire de clés RSA on ajoute le hash de la clé privée
        pathRSA=input("+ Saisir le chemin de votre clé privée: ")
        with open(pathRSA, "r") as fRSA:
            signRSA=parseRSA(fRSA.read())
        return sha256(signRSA)
    else:
        #---Si l'utilisateur ne possede pas de clés RSA on génère une paire de clés et on récupère le hash de sa clé publique
        print("+ Création d'une paire de clés RSA")
        nameKey = generateRSA()
        with open(nameKey+"_private.key", "r") as fRSA:
            signRSA=parseRSA(fRSA.read())
        return sha256(signRSA)
        #APPEL DE LA FONCTION DE CREATION DES CLES RSA

#--- Fonction qui permet de récupérer la clé publique de l'utilisateur
#- Amélioration : convertir le n en bytes et en hexa
def getPublicKey():
    pathRSA = input("+ Saisir le chemin de votre clé publique: ")
    e,n=getElementsFromKey(pathRSA)
    return e,n





#--- Fonction qui permet de générer une demande de signature de certificat (CSR)
def generateCertificate():
    nameCSR = input("+ Entrez le nom du certificat : ")
    with open(nameCSR+".txt","w") as ftextCSR:
        print("-----")
        print("You are about to be asked to enter information that will be incorporated into your certificate request. What you are about to enter is what is called a Distinguished Name or a DN. There are quite a few fields but you can leave some blank. For some fields there will be a default value.")
        print("-----")
        #--- Collect informations
        hashRSA = getPrivateSignature()
        e,n = getPublicKey()
        resultString = askUser()
        #--- Write the certificate
        ftextCSR.write("Certificate Request:")
        ftextCSR.write("\n\tData:")
        #VERSION
        ftextCSR.write("\n\t\tVersion: 0 (0x0)")
        #DEMANDER A l'UTILISATEUR LES DIFFERENTES INFOS
        ftextCSR.write("\n\t\tSubject: "+resultString)
        ftextCSR.write("\n\t\tSubject Public Key Info: ")
        ftextCSR.write("\n\t\t\tPublic Key Algorithm: rsaEncryption")
        ftextCSR.write("\n\t\t\tRSA Public Key: (1024 bits)")
        ftextCSR.write("\n\t\t\t\tModulus: (1024 bits)")
        ftextCSR.write("\n\t\t\t\t\t"+str(n))
        ftextCSR.write("\n\t\t\t\tExponent: "+str(e))
        #SIGNATURE NUMERIQUE DE L'ENTITE GENERANT LE CERTIFICAT (En Hexadecimal)
        ftextCSR.write("\n\t\t\tSignature Algorithm: sha256WithRSAEncryption")
        ftextCSR.write("\n\t\t\tSignature Value: "+hashRSA)
    with open(nameCSR+".csr","w") as fCSR:
        fCSR.write("-----BEGIN CERTIFICATE REQUEST-----\n")
        with open(nameCSR+".txt","r") as ftextCSR:
            fCSR.write(stringToBase64(ftextCSR.read()))
        fCSR.write("\n-----END CERTIFICATE REQUEST-----")
    os.remove(nameCSR+".txt")

#--- Fonction qui permet de signer un certificat
def signCSR():
    pathCSR = input("+ Saisir le chemin de la demande de signature que vous souhaitez signer: ")
    #- Affichage du certificat du demandeur
    print("_________________________________________________________")
    print("\n+ Affichage du certificat de l'utilisateur")
    print("_________________________________________________________")
    with open(pathCSR,"r") as fCSR:
        txtCSR = parseCSR(fCSR.read())
    print(base64ToString(txtCSR))
    print("_________________________________________________________")
    #- Verification de l'authenticite de la demande
    isOk = input("+ Le certificat du demandeur est-il valide (O) ou (N): ")
    while isOk != "O" and choice != "N":
        print("+ ERREUR: saisie incorrecte !\n+ Usage: O-Oui, N-Non")
        isOk = input("+ Le certificat du demandeur est-il valide (O) ou (N): ")
    if isOk == "O":
        #- Signature du certificat avec la clé privée de l'autorite de certification -- ajout de la date de signature et de la validite du certificat
        pathRSA=input("+ Saisir le chemin de la clé privée: ")
        with open(pathRSA, "r") as fRSA:
            signRSA=parseRSA(fRSA.read())
            signRSA=sha256(signRSA)
        #- On remplace le champ signatureValue de la signature du demandeur par la signature de l'autorite de certification
        newTxtCsr = changeField("Signature Value",signRSA,base64ToString(txtCSR))
        #- On ajoute les champs dates et expiration à la fin du certificat
        date = datetime.date.today()
        expiration = input("+ Quelle est la durée de validite du certificat (j): ")
        newTxtCsr = newTxtCsr + "\n\t\t\tDate: "+str(date)+"\n\t\t\tJ: "+expiration
        os.remove(pathCSR)
        with open(pathCSR,"w") as signedCert:
            signedCert.write("-----BEGIN CERTIFICATE-----\n")
            signedCert.write(stringToBase64(newTxtCsr))
            signedCert.write("\n-----END CERTIFICATE-----")
        


if __name__ == '__main__':
    print("_________________________________________________________\n>>>> 3: Signer / Générer un certificat <<<<")
    choice = input("+ Bienvenue dans l'espace de génération / signature des certificats\n+ Voulez vous générer un certificat (1), signer un certificat par une autorité de certification (2): ")
    while choice != "1" and choice != "2":
        print("+ ERREUR: saisie incorrecte !\n+ Usage: 1-Generation de certificat, 2-Signature d'un certificat")
        choice = input("+ Voulez vous générer une requete de certificat (1), signer un certificat par une autorité de certification (2): ")
    if choice == "1":
        generateCertificate()
        print("+ Le certificat a été généré avec succés.\n+ Fin du programme.")
        print("_________________________________________________________")
    elif choice == "2":
        signCSR()
        print("+ Fin du programme.")
        print("_________________________________________________________")
    