from Scripts import Symmetric as symm
from Scripts import async_enc as signal
from Scripts import keygen as keygen
from Scripts import certificate_sign as cert
from Scripts import certificate_verify as verifCert
from Scripts import knowledge_proof as ZKP
from Scripts import user
import sys

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
            option1 = {
                1 : 'Encrypt a message',
                2 : 'Decrypt a message',
                3 : 'Quit'
            }
            while True :
                choice1 = print_menu(option1)
                match choice1 :
                    case '1' :
                        symm.front_encryption()
                        break
                    case '2' :
                        symm.front_decryption()
                        break
                    case '3' | 'q' | 'quit' | 'exit':
                        break
                    case other :
                        print('[*]  Choose a valid option')
        case '2' :
            uSer = user.authenticate()
            option2 = {
                1 : 'Generate a pair of RSA',
                2 : 'Encrypt a message',
                3 : 'Decrypt a message',
                4 : 'Quit'
            }
            while True:
                print("+ Hello "+uSer.nom+" welcome to the RSA area.")
                choice2 = print_menu(option2)
                match choice2:
                    case '1':
                        keygen.generateRSA()
                    case '2':
                        keygen.cipherRSA(uSer)
                    case '3':
                        keygen.decipherRSA(uSer)
                    case '4' | 'q' | 'quit' | 'exit':
                        print("[*] Exiting...............")
                        break
                    case other :
                        print('Please choose a valid option')
        case '3' :
            uSer = user.authenticate()
            option3 = {
                1 : 'Generate a certificate request (CSR)',
                2 : 'Sign a certificate as the CA autority',
                3 : 'Quit'
            }
            while True:
                print("+ Hello "+uSer.nom+" welcome to the certificate area.")
                choice3=print_menu(option3)
                match choice3:
                    case '1':
                        cert.generateCertificate(uSer)
                    case '2':
                        autorite_cert,autorite_sequ=user.initialisation()
                        cert.signCSR(autorite_cert,autorite_sequ)
                    case '3' | 'q' | 'quit' | 'exit':
                        print("[*] Exiting...............")
                        break
                    case other :
                        print('Please choose a valid option')

        case '4' :
            option4 = {
                1 : 'Verify a certificate',
                2 : 'Quit',
            }
            while True:
                choice4=print_menu(option4)
                match choice4:
                    case '1':
                        autorite_cert,autorite_sequ=user.initialisation()
                        verifCert.verifyCertificate(autorite_sequ,autorite_cert)
                    case '2' | 'q' | 'quit' | 'exit':
                        print("[*] Exiting...............")
                        break
                    case other :
                        print('Please choose a valid option')
                
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
            option6 = {
                1 : 'Ask for a zero knowledge proof',
                2 : 'Quit',
            }
            while True:
                choice6=print_menu(option6)
                match choice6:
                    case '1':
                        uSer = user.authenticate()
                        autorite_cert,_=user.initialisation()
                        ZKP.zeroKnowledgeProof(uSer,autorite_cert)
                    case "q" | "exit" | "quit" | '2':
                        print("[*] Exiting...............")
                        break
                    case other:
                        print("Please choose a valid option")
                
        case '7' | 'q' | 'quit' | 'exit':
            print('[+]  Exiting.....')
            sys.exit()
        case other :
            print("[*]  Choose a valid option")

