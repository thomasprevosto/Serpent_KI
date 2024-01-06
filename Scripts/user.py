from keygen import generateRSA
from utils import *
import json,os
from datetime import datetime,timedelta

#Chemin de la database json des utilisateurs
database = "database.json"
#--- Class des utilisateurs qui utilisent le systeme de l'API.
class utilisateur:
    def __init__(self,nom=None):
        if nom is None:
            print("+ Creation d'un compte utilisateur.")
            self.nom = input("+ Saisir votre nom: ")
            self.mail = input("+ Saisir votre mail: ")
            self.phone = input("+ Saisir votre numero de telephone: ")
            print("+ Generation d'une paire de cles RSA")
            namekey=generateRSA()
            self.pubKey = namekey+"_public.key"
            self.priKey = namekey+"_private.key"
        else:
            self.nom = nom
    def getPersonalInformation(self):
        return {
            "nom": self.nom,
            "mail": self.mail,
            "phone": self.phone,
            "pubKey": self.pubKey,
            "priKey": self.priKey
        }
    def getName(self):
        return self.nom
    def getPublicKey(self):
        with open(self.pubKey,"r") as f:
            return (f.read())
    def getPrivateKey(self):
        with open(self.priKey,"r") as f:
            return (f.read())
    def signature(self):
        with open(self.priKey, "r") as fRSA:
            signRSA=parseRSA(fRSA.read())
            signRSA=sha256(signRSA)
        return signRSA
    def sauvegarder_donnees(self, utilisateurs, fichier):
        donnees = {"utilisateurs": []}
        for utilisateur in utilisateurs:
            donnees["utilisateurs"].append(utilisateur.getPersonalInformation())

        with open(fichier, "w") as f:
            f.write(json.dumps(donnees))
            f.write('\n')

    @classmethod
    def charger_donnees(cls, fichier):
        utilisateurs = []
        try:
            with open(fichier, "r") as f:
                donnees = json.load(f)
                for utilisateur_data in donnees["utilisateurs"]:
                    utilisateur = cls(utilisateur_data["nom"])
                    #utilisateur.nom = utilisateur_data["nom"]
                    utilisateur.mail = utilisateur_data["mail"]
                    utilisateur.phone = utilisateur_data["phone"]
                    utilisateur.pubKey = utilisateur_data["pubKey"]
                    utilisateur.priKey = utilisateur_data["priKey"]
                    utilisateurs.append(utilisateur)
        except FileNotFoundError:
            pass
        return utilisateurs

#CLASS de l'autorite de certification qui consulte les certificats, verifie leur authenticite et les signe.
class autoriteCert:
    #keyRSA
    pathPublicRSA="CA_public.key"
    pathPrivateRSA="CA_private.key"
    #initName of CA
    def __init__(self,nom):
        self.nom = nom
    def getName(self):
        return self.nom
    def getPublicKey(self):
        return self.pathPublicRSA
    def getPrivateKey(self):
        return self.pathPrivateRSA
    #Get RSA signature of CA
    def signature(self):
        with open(self.pathPrivateRSA, "r") as fRSA:
            signRSA=parseRSA(fRSA.read())
            signRSA=sha256(signRSA)
        return signRSA




#--- CLASS de l'autorite de sequestre qui permet de revoquer les certificats, de verifier la date ainsi que de les ajouter au dépot
class autoriteSequ:
    #initName of sequAut
    #depot --> Acceder aux certificats dans le dépot
    PATH_DEPOT = 'depot/'
    PATH_DEPOT_REVOK = 'depot_revok'
    def __init__(self,nom):
        self.nom = nom
    def getName(self):
        return self.nom
    #--- Affiche les certificats signes qui sont contenus dans le depot
    def afficherCertificat(self):
        print("+ ",self.nom," : 'Contenu du dépot'\n")
        fichiers = []
        # Parcourir les entrées dans le répertoire
        for entree in os.listdir(self.PATH_DEPOT):
            chemin_complet = os.path.join(self.PATH_DEPOT, entree)
            # Vérifier si l'entrée est un fichier et non un dossier
            if os.path.isfile(chemin_complet):
                fichiers.append(chemin_complet)
        for f in fichiers:
            #TEST si c'est un certificat -> Si oui on l'affiche
            if ".csr" in f:
                print("_________________________________________________________")
                print(f)
                print("_________________________________________________________")
                with open(f,"r") as cert:
                    print(base64ToString(parseCSR(cert.read())))
                print("_________________________________________________________")
    #--- On ajoute le certificat au depot lorsque l'on signe le certificat
    def ajouterAuDepot(self,cert):
        print("+ ",self.nom," : 'Ajout au depot du certificat'\n",cert)
    #--- Test de validite de la date du certificat
    def dateValid(self,cert):
        print("+ ",self.nom," : 'Test de la validite temporelle du certificat'")
        try:
            start_index = cert.find("Date: ") + len("Date: ")
            end_index = cert.find("\n", start_index)
            date_str = cert[start_index:end_index].strip()

            # Convertir la chaîne de date en objet datetime
            date_certificat = datetime.strptime(date_str, "%Y-%m-%d")

            # Extraire la durée de validité (en jours)
            j_index = cert.find("J: ") + len("J: ")
            j_end_index = cert.find("\n", j_index)
            j_str = cert[j_index:j_end_index].strip()
            validite_jours = int(j_str)

            # Calculer la date d'expiration
            date_expiration = date_certificat + timedelta(days=validite_jours)
            # Comparer avec la date actuelle
            return datetime.now() < date_expiration
        except ValueError as e:
            print("Erreur lors de la lecture du certificat:", e)
            return False
    def revoquerCert(self,pathCert):
        print("+ ",self.nom," : 'Revocation du certificat'\n")
        os.remove(pathCert)















#--- MAIN Temporaire
if __name__ == '__main__':
    print("+ Bienvenue dans l'API: GS15_api")
    GS15_Seq = autoriteSequ("GS15_Seq")
    GS15_Seq.afficherCertificat()
    choice = input("+ Desirez vous creer un compte (1) ou vous authentifier (2): ")
    try:
        utilisateurs = utilisateur.charger_donnees(database)
    except:
        utilisateurs = []
    while choice != "1" and choice != "2":
        print("+ ERREUR: saisie incorrecte !\n+ Usage: 1-Creation de compte, 2-Authentifier")
        choice = input("+ Desirez vous creer un compte (1) ou vous authentifier (2): ")    
    if choice == "1":
        user = utilisateur()
        utilisateurs.append(user)
        user.sauvegarder_donnees(utilisateurs,database)
        print("+ Notez les informations pour vous authentifier:\n\tUsername: "+user.getName()+"\n\tPrivate Key: \n"+user.getPrivateKey()+"\n\Public Key: \n"+user.getPublicKey())
    elif choice == "2":
        utilisateurs = utilisateur.charger_donnees("database.json")
        test = True
        while test:
            name = input("+ Saisir votre nom d'utilisateur: ")
            pKey = input("+ Saisir votre clé privée: ")
            for u in utilisateurs:
                print(parseRSA(u.getPrivateKey()))
                if u.getName() == name and parseRSA(u.getPrivateKey()) == (pKey):
                    test = False
                    user = u
                    print("+ Authentification reussie")
            if test:
                print("+ ERREUR: Echec de l'authentification.")
        print("+ Bonjour "+user.getName()+" bienvenue dans l'API GS15_api")
