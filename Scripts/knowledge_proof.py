from Scripts.keygen import getElementsFromKey
from Scripts.utils import *
from Scripts.user import *

import random,math,time

def guillouQuisquaterEngagement(e, n):
    """
    function: guillouQuisquater Engagement
    1ère Étape d'engagement pour le Prouveur.
    e: exposant de clé publique
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
    function: guillouQuisquaterDefi
    2ème Étape de défi pour le vérifieur.
    e: exposant de clé publique
    """
    c = random.randint(1, e - 1)
    return c

def guillouQuisquaterReponse(y, d, e, c, n):
    """
    Étape de réponse par Alice.
    y: nombre aléatoire choisi par Alice
    d: signature d'Alice (représentant la clé privée)
    c: défi choisi par Bob
    n: module RSA
    """
    Z = (y * pow(d, c)) % n
    D = pow(d,e,n)

    return Z,D

def guillouQuisquaterVerification(y, D, c, Z, e, n):
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
    val2 = (Y*pow(D,c))%n
    print("val2:",val2)
    if val1 == val2:
        print("+ Test of Guillou Quisquater is valid")

def testGuillouQuisquater(prouveur):
    #ICI CA est le prouveur
    #ca = autoriteCert("GS15_CA")
    e,n = getElementsFromKey(prouveur.getPublicPathKey()) 
    d,n = getElementsFromKey(prouveur.getPrivatePathKey())

    y,Y = guillouQuisquaterEngagement(e,n)
    print("+ Premiere étape \ny(random):",y,"\nY: ",Y)
    c=guillouQuisquaterDefi(e)
    print("+Deuxieme etape \nc:",c)
    Z,D=guillouQuisquaterReponse(y,d,e,c,n)
    print("+Troisieme etape\nZ:",Z)
    guillouQuisquaterVerification(y,D,c,Z,e,n)

def zeroKnowledgeProof(user,autorite):
    print("+ Hello "+user.nom+" welcome to the ZKP area.")
    print("+ List of people you can try with:")
    print("\t- "+autorite.getName())
    try:
        utilisateurs = utilisateur.charger_donnees(database)
    except:
        utilisateurs = []
    for u in utilisateurs:
        if not user.nom == u.nom:
            print("\t""- "+u.nom)
    name = input("+ Who do you want to try with the Zero-Knowledge-Proof of Guillou-Quisquater: ")
    if name == "GS15_CA":
        prouveur = autorite
    else:
        for u in utilisateurs:
            if u.nom == name:
                prouveur = u
    print(prouveur.getName())
    testGuillouQuisquater(prouveur)

if __name__ == '__main__':
    ca = autoriteCert("GS15_CA")
    e,n = getElementsFromKey(ca.getPublicKey()) 
    d,n = getElementsFromKey(ca.getPrivateKey())
    
    y,Y = guillouQuisquaterEngagement(e,n)
    print("+ Premiere étape \ny(random):",y,"\nY: ",Y)
    c=guillouQuisquaterDefi(e)
    print("+Deuxieme etape \nc:",c)
    Z,D=guillouQuisquaterReponse(y,d,e,c,n)
    print("+Troisieme etape\nZ:",Z)
    guillouQuisquaterVerification(y,d,c,Z,e,n)

