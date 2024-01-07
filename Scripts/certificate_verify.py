from Scripts.certificate_sign import *
from Scripts.user import *

#--- Script permettant de vérifier l'authenticite et la validite des certificats.
#- Verification de l'autorite de certification et de la date du certificat.
fichier = "database.json"
PATH_DEPOT = 'Serpent_KI/Resources/depot/'
#--- Fonction qui permet d'afficher un certificat
def printCert(autorite_sequ):
    ok = True
    while ok :
        if not autorite_sequ.afficherCertificat():
            time.sleep(3)
            return None
        pathCSR = input("\n+ Saisir le chemin (relatif) du certificat que vous souhaitez vérifier: ")
        #- Affichage du certificat
        print("_________________________________________________________")
        print("\n+ Affichage du certificat")
        print("_________________________________________________________")
        with open(PATH_DEPOT+pathCSR,"r") as fCSR:
            txtCSR = parseCSR(fCSR.read())
        print(base64ToString(txtCSR))
        print("_________________________________________________________")
        choice = input("+ Voulez vous vérifier ce certificat - Oui (O) ou Non (N): ")
        while choice not in ["O","N"]:
            print("+ ERREUR: Saisie Incorrecte\n+ Usage: Oui (O) - Non (N)")
            choice = input("+ Voulez vous vérifier ce certificat - Oui (O) ou Non (N): ")
        if choice == "O":
            return pathCSR
        else:
            choice2 = input("+ Souhaitez vous afficher un autre certificat - Oui (O) ou Non (N): ")
            while choice2 not in ["O","N"]:
                print("+ ERREUR: Saisie Incorrecte\n+ Usage: Oui (O) - Non (N)")
                choice2 = input("+ Souhaitez vous afficher un autre certificat - Oui (O) ou Non (N): ")
            if choice2 == "N":
                print("+ Fin du programme.")
                return None

#--- Fonction qui permet de vérifier l'authenticité de la signature de l'autorite
def verifierSignature(signature_value, autorite_CA):
    return signature_value == autorite_CA.signature()

def verifierEmetteur(nom_emetteur, autorite_CA):
    #print(nom_emetteur,autorite_CA.getName())
    return nom_emetteur == autorite_CA.getName()

#--- Fonction qui permet de vérifier l'authenticite et la validite des certificats --- Certificats signes
def verifyCertificate(autorite_sequ,autorite_CA):
    pathCERT = printCert(autorite_sequ)
    if pathCERT is None:
        return
    with open(PATH_DEPOT+pathCERT,"r") as fCERT:
        text_cert = base64ToString(parseCSR(fCERT.read()))
    #Verification de l'emetteur: Ici on accepte uniquement les certificats qui dépendent de l'emetteur: GS15_CA --> Si non, le certificat est révoqué par l'autorite de sequestre
    print("+ Verification de l'emetteur du certificat")
    if verifierEmetteur(extraire_field("Autorité de Certification: ",text_cert),autorite_CA):
        print("\t- OK: L'emetteur correspond à:"+autorite_CA.getName())
    else:
        print("\t-WARNING: l'emetteur n'est pas correspondant.")
        autorite_sequ.revoquerCert(pathCERT)
        time.sleep(10)
        return
    #Verification de la signature du certificat --> On verifie que la signature du certificat correspond à la signature de l'autorite de cert
    print("+ Verification de l'authenticite de la signature de l'emetteur")
    if verifierSignature(extraire_field("Signature Value: ",text_cert),autorite_CA):
        print("\t-OK: La signature correspond à la signature de "+autorite_CA.getName())
    else:
        print("\t-WARNING: La signature n'est pas correspondante")
        autorite_sequ.revoquerCert(pathCERT)
        time.sleep(10)
        return
    #Verification de la validite temporelle: La verification de la validite temporelle se fait par l'autorite de sequestre --> Si non, le certificat est révoqué par l'autorite de sequestre
    if autorite_sequ.dateValid((text_cert)):
        print("\t- La date du certificat est valide.")
        time.sleep(10)
    else:
        print("WARNING: Le certificat à expiré")
        autorite_sequ.revoquerCert(pathCERT)
        time.sleep(10)

if __name__ == '__main__':
    #INITIALISATION des autorites
    autorite_CA = autoriteCert("GS15_ca")
    autorite_sequ = autoriteSequ("GS15_SEQ")
    verifyCertificate(autorite_sequ,autorite_CA)