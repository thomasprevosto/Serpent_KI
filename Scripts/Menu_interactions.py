from Scripts import Symmetric as symm
from Scripts import async_enc as signal
from Scripts import keygen as keygen
from Scripts import user
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
            os.system('cls')
            user.authenticate()
            option2 = {
                1 : 'Generate a pair of RSA',
                2 : 'Encrypt a message',
                3 : 'Decrypt a message',
                4 : 'Quit'
            }
            while True:
                os.system('cls')
                choice2 = print_menu(option2)
                match choice1 :
                    case '1':
                        os.system('cls')
                        user.changeKey()
                    case '2':
                        keygen.cipherRSA()
                    case '3':
                        keygen.decipherRSA()
                    case '4' | 'q' | 'quit' | 'exit':
                        print("[*] Exiting...............")
                        break
                    case other :
                        print('Please choose a valid option')
        case '3' :
            print('To do')
        case '4' :
            print('To do')
        case '5':
            while True:
                users = signal.load_user()
                choice5 = input("[1] - Create a user\n[2] - Send a message\n[3] - Read a message\n[4] - Exit\n")
                match choice5:
                    case "1":
                        name, name2 = signal.create_user(users)
                        users = signal.first_message(name, name2, users)
                    case "2":
                        name = input("[+] LOGIN : ")
                        name2 = input("Send a message to : ")
                        users = signal.message_user(users, name, name2)
                    case "3":
                        signal.read_message(users)
                    case "q" | "exit" | "quit" | '4':
                        print("[*] Exiting...............")
                        break
                    case other:
                        print("Please choose a valid option")

        case '6':
            print('To do')
        case '7' | 'q' | 'quit' | 'exit':
            print('[+]  Exiting.....')
            sys.exit()
        case other :
            print("[*]  Choose a valid option")

