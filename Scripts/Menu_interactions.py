from Scripts import Symmetric as symm
import sys
import os

def print_menu(options) :
    for key in options.keys() :
        print('[',key,']    ',options[key])
    return input('Enter your choice :   ')

## Ajouter une fonction clear_screen à chaque itération de la loop
## Ajouter une bannière ASCII fixe pendant l'execution du programme
## Ajouter des couleurs de police

def check_choice(choice):
    match choice :

        case '1' :      #Import Symmetric.py
            os.system('cls')
            option1 = {
                1 : 'Encrypt a message',
                2 : 'Decrypt a message',
                3 : 'Quit'
            }
            while True :
                os.system('cls')
                choice1 = print_menu(option1)
                match choice1 :
                    case '1' :
                        os.system('cls')
                        symm.front_encryption()
                        break
                    case '2' :
                        os.system('cls')
                        symm.front_decryption()
                        break
                    case '3' | 'q' | 'quit' | 'exit':
                        break
                    case other :
                        print('[*]  Choose a valid option')
        case '2' :
            print('To do')
        case '3' :
            print('To do')
        case '4' :
            print('To do')
        case '5':
            print('To do')
        case '6':
            print('To do')
        case '7' | 'q' | 'quit' | 'exit':
            print('[+]  Exiting.....')
            sys.exit()
        case other :
            print("[*]  Choose a valid option")

