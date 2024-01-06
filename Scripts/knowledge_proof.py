from keygen import getElementsFromKey
from utils import *
import random
from user import *

import random

def guillouQuisquaterEngagement(v, n, S_A):
    """
    Étape d'engagement par Alice.
    v: exposant de vérification
    n: module RSA
    S_A: signature d'Alice (représentant la clé privée)
    """
    r = random.randint(1, n - 1)
    x = pow(r, v, n)
    return r, x

def guillouQuisquaterDefi(v):
    """
    Étape de défi par Bob.
    v: exposant de vérification
    """
    e = random.randint(1, v - 1)
    return e

def guillouQuisquaterReponse(r, S_A, e, n):
    """
    Étape de réponse par Alice.
    r: nombre aléatoire choisi par Alice
    S_A: signature d'Alice (représentant la clé privée)
    e: défi choisi par Bob
    n: module RSA
    """
    y = (r * pow(S_A, e)) % n
    return y

def guillouQuisquaterVerification(x, J_A, e, y, v, n):
    """
    Étape de vérification par Bob.
    x: engagement envoyé par Alice
    J_A: clé publique d'Alice
    e: défi choisi par Bob
    y: réponse d'Alice
    v: exposant de vérification
    n: module RSA
    """
    check_value = (pow(J_A, e, n) * pow(y, v, n)) % n
    print("check: "+str(check_value))
    return check_value == x and check_value != 0

if __name__ == '__main__':
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
    v,n = getElementsFromKey(ca.getPublicKey())  # Exemple d'exposant public
    d,n = getElementsFromKey(ca.getPrivateKey())# Exemple de module RSA

    # Exemple de valeurs
    #n = # Le module RSA
    #v = # Exposant de vérification (doit être convenu ou choisi)
    S_A = d# Signature d'Alice (représentant la clé privée)
    J_A = v# Clé publique d'Alice (correspondant à la signature)

    # Étape d'engagement
    r, x = guillouQuisquaterEngagement(v, n, S_A)
    print("Engagement: ", x)

    # Étape de défi
    e = guillouQuisquaterDefi(v)
    print("Défi: ", e)

    # Étape de réponse
    y = guillouQuisquaterReponse(r, S_A, e, n)
    print("Réponse: ", y)

    # Étape de vérification
    if guillouQuisquaterVerification(x, J_A, e, y, v, n):
        print("Vérification réussie.")
    else:
        print("Échec de la vérification.")
