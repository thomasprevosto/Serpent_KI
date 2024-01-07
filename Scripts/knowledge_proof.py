from Scripts.keygen import getElementsFromKey
from Scripts.utils import *
from Scripts.user import *

import random,math
import random

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

def testGuillouQuisquater(prouveur,verifieur):
    ca = autoriteCert("GS15_CA")
    e,n = getElementsFromKey(ca.getPublicKey()) 
    d,n = getElementsFromKey(ca.getPrivateKey())

    y,Y = guillouQuisquaterEngagement(e,n)
    print("+ Premiere étape \ny(random):",y,"\nY: ",Y)
    c=guillouQuisquaterDefi(e)
    print("+Deuxieme etape \nc:",c)
    Z=guillouQuisquaterReponse(y,d,c,n)
    print("+Troisieme etape\nZ:",Z)
    guillouQuisquaterVerification(y,d,c,Z,e,n)

#MAIN temp
if __name__ == '__main__':
    ca = autoriteCert("GS15_CA")
    e,n = getElementsFromKey(ca.getPublicKey()) 
    d,n = getElementsFromKey(ca.getPrivateKey())
    
    y,Y = guillouQuisquaterEngagement(e,n)
    print("+ Premiere étape \ny(random):",y,"\nY: ",Y)
    c=guillouQuisquaterDefi(e)
    print("+Deuxieme etape \nc:",c)
    Z=guillouQuisquaterReponse(y,d,c,n)
    print("+Troisieme etape\nZ:",Z)
    guillouQuisquaterVerification(y,d,c,Z,e,n)

