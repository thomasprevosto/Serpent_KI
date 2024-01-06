from Scripts.keygen import *
import csv
from Scripts.Symmetric import encryption,decryption,output_to_file,input_console_message,read_file_convert
from certificate_sign import sha256
import os
import bitarray
import random

global p,db_path
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
db_path = "../Server/server_users.csv"


"""----------Key Generation/Derivation Functions----------"""
def DH_keygen() :
    g = 2   #Generator
    sk = random.randrange(2,p-1)
    pk = pow(g,sk,p)

    return sk,pk

def DH(sk,pub):
    return hex(pow(pub,sk,p))[2:]

def hmac256(key:str,message) :
    #Key must be 64 bytes = 512 bits with \x00 padding
    if len(key) < 128:
        key += '0' * (128 - len(key))
    elif len(key) > 128:
        key = sha256(key)
        key += '0' * (128 - len(key))

    k1 = key
    k2 = key
    ipad = '36'*64
    opad = '5c'*64

    k1 = hex(int(k1,16) ^ int(ipad,16))[2:]
    k2 = hex(int(k2,16) ^ int(opad,16))[2:]
    h_1 = sha256(k1 + message)
    hmac = sha256(k2 + h_1)

    return hmac

def Ratchet(key) :
    message_key,chain_key = KDF(key)
    return chain_key,message_key

def KDF(key) :
    message_key = hmac256(key,'01')
    chain_key = hmac256(key,'02')
    return message_key,chain_key

"""----------File Utils Functions---------"""
def parse_filename(file_path):

    filename = os.path.basename(file_path)

    parts = filename.split("_")
    #Inverse the names so that the receiving ratchet gets updated
    name2 = parts[0]
    name = parts[1]
    counter = int(parts[2].split(".")[0])  # Remove extension from filename
    return name, name2, counter

def message_output(message,file_name):
    directory = input("Directory path : ")
    file_path = os.path.join(directory, file_name)
    try:
        with open(file_path, 'wb') as file:
            if isinstance(message, str):  # If Ciphertext is a string
                text_bits = bitarray.bitarray(message)
                file.write(text_bits.tobytes())
            elif isinstance(message, list):  # If ciphertext is a list of strings
                text_bits = bitarray.bitarray()
                for block in message:
                    text_bits.extend(bitarray.bitarray(block))
                file.write(text_bits.tobytes())
            else:
                print("Bad Format.")
                return False

        print(f"Encrypted message located at : {file_path}")
        return True
    except Exception as e:
        print(f"File Writing Error : {e}")
        return False

def format_filename(name, name2, counter):
    return f"{name}_{name2}_{str(counter)}.enc"



"""---------User Utils Function----------"""
def load_user():    #Load database in memory
    users = []
    try:
        with open(db_path) as csvfile:
            server_reader = csv.reader(csvfile,delimiter=',')
            for row in server_reader:
                if len(row) != 0:
                    users.append(row)
        return users
    except FileNotFoundError:
        print(f"Database not found : {db_path}\nPlease create first the users\n") #Path to Database can be modified
        return users
    except Exception as e:
        print(f"Error : {e}")
        return None

def save_users(users):  #Overwrite the CSV Database
    try:
        with open(db_path,mode='w') as csvfile:
            server_writer = csv.writer(csvfile,delimiter=',',quotechar='"')
            for i in range(len(users)):
                server_writer.writerow(users[i])
    except FileNotFoundError:
        print(f"Database not found : {db_path}\n")  # Path to Database can be modified
        return None
    except Exception as e:
        print(f"Error : {e}")
        return None
def user_check(name,users):
    for index,row in enumerate(users):
        if row[0] == name:
            return 0
    return 1

def create_user(users):
    name = input("Input the name of your user : ")
    if user_check(name,users) == 0:
        print(f"The user [{name}] already exists !")
        return
    print(f"\n[*] Connected as [{name}] \n")
    name2 = input("Input the name of the user you want to text : ")
    return name,name2

def find_correspondence(users,name,name2):  #Extract the users from the database as well as their index for further modifications
    for index, row in enumerate(users):
        if row[0] == name and row[1] == name2:
            return users[index],index
    print("[-] Correspondence not found")
    return None,None

"""----------Message Sending Functions----------"""

def message_encryption(name,name2,sh_k,counter:int):
    print(f"[+] Message to [{name2}] :\n")
    message = input_console_message()
    message_key,chain_key = Ratchet(sh_k)
    cipher = encryption(message,message_key)
    counter = int(counter)+1
    message_name = format_filename(name,name2,counter)
    message_output(cipher,message_name)
    return chain_key

def first_message(name,name2,users):
    """Diffie-Hellman Key Exchange --- Here local exchange"""
    sk_1,pub_1 = DH_keygen()
    sk_2, pub_2 = DH_keygen()
    sh_k = DH(sk_1,pub_2)

    """Key Derivation Functions to encrypt the message"""
    message = input_console_message()
    message_key,chain_key = Ratchet(sh_k)
    cipher = encryption(message,message_key)
    message_name = format_filename(name,name2,1)
    message_output(cipher,message_name)

    """
    Append the pair of users into the database (2 lines)
    [Name,Name2,secret_key,other_public_key,Ratchet session key,message_counter]
    """

    users.append([name,name2,sk_1,pub_2,chain_key,1]) #Sender
    users.append([name2, name, sk_2, pub_1, "", 0]) #Receiver -- Message needs to be read
    save_users(users)
    return users

def message_user(users,name,name2):

    user_line,index = find_correspondence(users,name,name2)

    if user_line == None:
        #First message exchange between the 2 users
        print(f"[*]Creating communication between [{name}] and [{name2}] .........")
        first_message(name,name2,users)
    else:
        user2_line,index2 = find_correspondence(users,name2,name)
        if int(user_line[5]) < int(user2_line[5]): #Messages must be first read to even the counter and the session keys
            message_counter = int(user2_line[5]) - int(user_line[5])
            print(f"You have {message_counter} message(s) waiting from {name2}, please read them in order before texting\n")
            return None
        else:
            chain_key = message_encryption(name,name2,user_line[4],user_line[5])
            users[index][5] = int(users[index][5]) + 1 #Message counter update
            users[index][4] = chain_key
            save_users(users)
            return users

"""-----Message reading functions-----"""
def message_decryption(name2,chain_key,message):
    print(f"[*] Message from [{name2}]\n")
    message_key,chain_key = Ratchet(chain_key)
    plaintext = decryption(message,message_key)
    output_to_file(plaintext)
    return chain_key


def read_message(users):
    file_path = input("Path to the message (.enc) : ")
    message = read_file_convert(file_path)
    name_f, name2_f, counter_f = parse_filename(file_path)
    user_line,index = find_correspondence(users,name_f,name2_f)
    if int(counter_f) == 1 and (int(user_line[5]) == 0):
        #First message to be read from the other user --> the DH output rootkey needs to be calculated
        rootkey = DH(int(user_line[2]),int(user_line[3]))
        chain_key = message_decryption(name2_f,rootkey,message)
    elif int(counter_f) < (int(user_line[5])+1):
        #Prevent user from reading a message out of order (ratchet key will change and former message will be lost)
        inbox = int(counter_f) - int(user_line[5])
        print(f"Message can't be read --- Please read the messages in order\n{inbox} message(s) from {name2_f} in inbox")
        return
    else:
        chain_key = message_decryption(name2_f,user_line[4],message)
    #Update the database about the ratchet
    users[index][5] = int(users[index][5])+1  # Message counter update
    users[index][4] = chain_key
    save_users(users)
    return None



if __name__ == '__main__':
    while True:
        users = load_user()
        choice = input("[1] - Create a user\n[2] - Send a message\n[3] - Read a message\n[4] - Exit\n")
        match choice:
            case "1":
                name,name2 = create_user(users)
                users = first_message(name,name2,users)
            case "2" :
                name = input("[+] LOGIN : ")
                name2 = input("Send a message to : ")
                users = message_user(users,name,name2)
            case "3":
                read_message(users)
            case "q" | "exit" | "quit" | '4':
                print("[*] Exiting...............")
                break
            case other :
                print("Please choose a valid option")
