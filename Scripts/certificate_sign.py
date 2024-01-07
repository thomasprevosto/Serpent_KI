#CE SCRIPT comptient :  La génération des demandes de certificats (CSR) -- La génération des certificats -- La signature des certificats
#---Hash Input message

from keygen import getElementsFromKey,parseRSA,generateRSA,stringToBase64,base64ToString
from user import autoriteCert,utilisateur
import os
from datetime import date
from utils import *


fichier='database.json'
#-----------------------------------------------------------------------------------------CSR FUNCTIONS
def changeField(champ_a_modifier,valeur_du_champ,text_cert):
    lignes = ""
    list = text_cert.split("\n")
    for ligne in list:
        if champ_a_modifier in ligne:
            lignes = lignes + ("\n\t\t\t"+champ_a_modifier+": "+valeur_du_champ)
        else:
            lignes = lignes + (ligne)+"\n"
    return lignes

#--- Fonction qui permet de vérifier l'authenticite d'un CSR en regardant si la signature du demandeur correspond à une signature de la db.json
def verifyCSR(pathCSR):
    # Lire le contenu du CSR
    with open(pathCSR, "r") as file:
        csrContent = base64ToString(parseCSR(file.read()))
    
    # Afficher le CSR
    print("Contenu de la demande de certificat:")
    print(csrContent)

    # Extraire la signature du CSR
    csrSignature = extraire_signature_valeur(csrContent)
    print(csrSignature)

    utilisateurs = utilisateur.charger_donnees(fichier)
    
    # Vérifier la signature
    for user in utilisateurs:
        # Calculer la signature attendue
        expectedSignature = user.signature()        
        #print(expectedSignature)
        if csrSignature == expectedSignature:
            print(f"Le certificat est valide. Correspond à l'utilisateur: {user.getName()}")
            return True

    print("Le certificat est invalide ou ne correspond à aucun utilisateur.")
    return False
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
def signCSR(autorite):
    pathCSR = input("+ Saisir le chemin de la demande de signature que vous souhaitez signer: ")
    print("_________________________________________________________")
    print("\n+ Affichage du certificat de l'utilisateur")
    print("_________________________________________________________")
    with open(pathCSR, "r") as fCSR:
        txtCSR = parseCSR(fCSR.read())
    print(base64ToString(txtCSR))
    print("_________________________________________________________")

    isOk = input("+ Le certificat du demandeur est-il valide (O) ou (N): ")
    while isOk not in ["O", "N"]:
        print("+ ERREUR: saisie incorrecte !\n+ Usage: O-Oui, N-Non")
        isOk = input("+ Le certificat du demandeur est-il valide (O) ou (N): ")

    if isOk == "O":
        # Signature du certificat avec la clé privée de l'autorité de certification
        signRSA = autorite.signature()
        newTxtCsr = changeField("Signature Value", signRSA, base64ToString(txtCSR))

        # Ajout des champs date, expiration, et nom de l'autorité de certification
        dateToday = date.today()
        expiration = input("+ Quelle est la durée de validite du certificat (j): ")
        newTxtCsr = newTxtCsr + "\n\t\t\tDate: "+str(dateToday)+"\n\t\t\tJ: "+expiration
        newTxtCsr = newTxtCsr + "\n\t\t\tAutorité de Certification: "+autorite.getName()

        os.remove(pathCSR)
        with open(pathCSR, "w") as signedCert:
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
        autorite_cert = autoriteCert("GS15_ca")
        signCSR(autorite_cert)
        print("+ Fin du programme.")
        print("_________________________________________________________")
    