from keygen import getElementsFromKey
from utils import *
import random,math
from user import *

import random

def guillouQuisquaterEngagement(e, n):
    """
    Étape d'engagement par Alice.
    e: exposant 
    n: module RSA
    """
    while True:
        y = random.randint(2, n - 1)
        if y % n != 0:
            Y = pow(y, e, n)
            if math.gcd(y,n)>1:
                continue
            else:
                return y,Y

def guillouQuisquaterDefi(e):
    """
    Étape de défi par Bob.
    e: exposant de clé publique
    """
    c = random.randint(1, e - 1)
    return c

def guillouQuisquaterReponse(y, d, c, n):
    """
    Étape de réponse par Alice.
    y: nombre aléatoire choisi par Alice
    d: signature d'Alice (représentant la clé privée)
    c: défi choisi par Bob
    n: module RSA
    """
    Z = (y * pow(d, c)) % n
    return Z

def guillouQuisquaterVerification(y, d, c, Z, e, n):
    """
    Étape de vérification par Bob.
    y: Premier nombre aleatoire
    d: Secret
    c: défi choisi par Bob
    Z: réponse d'Alice
    e: exposant de vérification
    n: module RSA
    """
    #PREMIERE VALEUR
    val1 = pow(Z,e,n)
    print("val1:",val1)
    #PUBLIC X
    Y = pow(y,e,n)
    #PRIVATE Y
    D = pow(d,e,n)
    val2 = (Y*pow(D,c))%n
    print("val2:",val2)
    if val1 == val2:
        print("ok")

if __name__ == '__main__':
    ca = autoriteCert("GS15_CA")
    e,n = getElementsFromKey(ca.getPublicKey()) 
    d,n = getElementsFromKey(ca.getPrivateKey())
    #e=3
    #n=101
    #-y: secret x: premier nombre aléatoire
    y,Y = guillouQuisquaterEngagement(e,n)
    print("+ Premiere étape \ny(random):",y,"\nY: ",Y)
    c=guillouQuisquaterDefi(e)
    print("+Deuxieme etape \nc:",c)
    Z=guillouQuisquaterReponse(y,d,c,n)
    print("+Troisieme etape\nZ:",Z)
    guillouQuisquaterVerification(y,d,c,Z,e,n)

    """
    print("+ Bienvenue dans l'API: GS15_api")
    choice = input("+ Desirez-vous creer un compte (1) ou vous authentifier (2): ")

    # Chargement ou initialisation des utilisateurs
    try:
        utilisateurs = utilisateur.charger_donnees(database)
    except:
        utilisateurs = []

    # Boucle de saisie de choix
    while choice not in ["1", "2"]:
        print("+ ERREUR: saisie incorrecte !\n+ Usage: 1-Creation de compte, 2-Authentifier")
        choice = input("+ Desirez-vous creer un compte (1) ou vous authentifier (2): ")

    # Création de compte ou authentification
    if choice == "1":
        # Code pour la création de compte...
        user = utilisateur()
        utilisateurs.append(user)
        user.sauvegarder_donnees(utilisateurs,database)
        print("+ Notez les informations pour vous authentifier:\n\tUsername: "+user.getName()+"\n\tPrivate Key: \n"+user.getPrivateKey()+"\n\Public Key: \n"+user.getPublicKey())
    elif choice == "2":
        # Code pour l'authentification...
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
    
    # Simuler un test de Guillou-Quisquater
    ca = autoriteCert("CA")  # Création d'une instance de l'autorité de certification

    # On récupere les valeurs de l'autorite de certification
    e,n = getElementsFromKey(ca.getPublicKey())  # Exemple d'exposant public
    d,n = getElementsFromKey(ca.getPrivateKey())# Exemple de module RSA

    # Exemple de valeurs
    #n = # Le module RSA
    #v = # Exposant de vérification (doit être convenu ou choisi)
    S_A = d# Signature d'Alice (représentant la clé privée)
    J_A = e# Clé publique d'Alice (correspondant à la signature)

    # Étape d'engagement
    r, x = guillouQuisquaterEngagement(e, n, S_A)
    print("Engagement: ", x)

    # Étape de défi
    e = guillouQuisquaterDefi(e)
    print("Défi: ", e)

    # Étape de réponse
    y = guillouQuisquaterReponse(r, S_A, e, n)
    print("Réponse: ", y)

    # Étape de vérification
    if guillouQuisquaterVerification(x, J_A, e, y, v, n):
        print("Vérification réussie.")
    else:
        print("Échec de la vérification.")
    """