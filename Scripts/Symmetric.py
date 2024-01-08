from Resources.Serpent import *
import copy
import random
import bitarray
import sys

"""--------------General Functions-------------------"""
def circular_left_shift(value, n, bit_length=32):
    return ((value << n) | (value >> (bit_length - n))) & 0xFFFFFFFF

def circular_right_shift(value, n, bit_length=32):
    return ((value >> n) | (value << (bit_length - n))) & 0xFFFFFFFF

def permutation_initiale(block):
    perm_block = ''
    for i in range(128):
        perm_block += block[IPTable[i]]
    return perm_block

def permutation_finale(block):
    perm_block = ''
    for i in range(0,128):
        perm_block += block[FPTable[i]]
    return perm_block

def generate_sbox_permutation(sbox):
    #Permute sbox
    for index_box in range(32):
        for index_bits in range(16):
            i = index_bits + sbox[index_box][index_bits]
            j = sbox[i][index_bits]
            sbox[index_box][index_bits] , sbox[index_box][j] = sbox[index_box][j] , sbox[index_box][index_bits]

def generate_round_keys(master_key):
    omega = 0x9e3779b9
    # Convert the master key in bits
    master_key_bits = bin(int(master_key, 16))[2:].zfill(256)
    assert len(master_key_bits) == 256
    # Create 8 first key blocks (32 bits)
    block_keys = [master_key_bits[i:i+32] for i in range(0, 256, 32)][:8]

    # Generate last 124 key blocks
    for i in range(8, 132):
        KEY = int(block_keys[i - 8], 2) ^ int(block_keys[i - 5], 2) ^ int(block_keys[i - 3], 2) ^ int(block_keys[i - 1], 2) ^ omega ^ i
        KEY = circular_left_shift(KEY,11) & 0xFFFFFFFF  # Assure que le résultat est un nombre de 32 bits
        KEY = format(KEY, '032b')
        assert len(KEY) == 32
        block_keys.append(KEY)

    #Generate Iteration keys
    round_keys = [0] * 33
    for i in range(0,33) :
        round_keys[i] = str(block_keys[i*4]+block_keys[i*4+1]+block_keys[i*4+2]+block_keys[i*4+3])
    return round_keys

"""------------------INPUT/OUTPUT FUNCTION---------------------------"""

def input_console_message():
    message = input("Input the message to encrypt : ")

    # Convert in bits
    message_bits = bitarray.bitarray()
    message_bits.frombytes(message.encode('utf-8'))

    # Check length
    message_length = len(message_bits)

    # Padding
    if message_length < 128:
        #Pad the message with '0' if length < 128 bits
        message_padding = 128 - message_length
        message_bits.extend([0] * message_padding)
        blocks = [message_bits.to01()]
        blocks.append(bin(message_padding)[2:].zfill(128))
        return blocks
    elif message_length == 128:
        blocks = [message_bits.to01()]
        blocks.append(bin(int(0))[2:].zfill(128))
        return blocks
    else:
        #Slice the message in 128 bits blocks
        blocks = [message_bits[i:i + 128] for i in range(0, message_length, 128)]

        #Padding
        message_padding = 0
        for i in range(len(blocks)):
            if len(blocks[i]) < 128:
                message_padding = 128 - len(blocks[i])
                blocks[i].extend([0] * message_padding)
            blocks[i] = blocks[i].to01()
        blocks.append(bin(message_padding)[2:].zfill(128))
        return blocks

def read_file_convert(file_path):
    try:
        # Read the content of the file
        with open(file_path, 'rb') as file:
            file_content = file.read()

        # Convert the file bytes in bits
        file_bits = bitarray.bitarray()
        file_bits.frombytes(file_content)

        # Check file length
        file_length = len(file_bits)
        # Apply padding
        if file_length < 128:
            # Pad with 0 if block length < 128 bits
            file_padding = (128 - file_length)
            file_bits.extend([0] * file_padding)
            blocks = [file_bits.to01()]

            blocks.append(bin(file_padding)[2:].zfill(128))
            return blocks.to01()  # Return the bit string
        elif file_length == 128:
            blocks = [file_bits.to01()]
            blocks.append(bin(file_padding)[2:].zfill(128))
            return blocks.to01()
        else:
            # Cut the file content in blocks of 128 bits
            blocks = [file_bits[i:i + 128] for i in range(0, file_length, 128)]

            # Apply the padding to the last block if last block length < 128 bits
            file_padding = 0
            for i in range(len(blocks)):
                if len(blocks[i]) < 128:
                    file_padding = 128 - len(blocks[i])
                    blocks[i].extend([0] * file_padding)


            for i in range(len(blocks)) :
                blocks[i] = blocks[i].to01()
            blocks.append(bin(file_padding)[2:].zfill(128))
            return blocks  #Return list of blocks

    except FileNotFoundError:
        print(f"File not found : {file_path}")
        return None
    except Exception as e:
        print(f"Error : {e}")
        return None

def output_to_file(text):
    file_path = input("File path : ")
    try:
        with open(file_path, 'wb') as file:
            if isinstance(text, str):  # If Ciphertext is a string
                text_bits = bitarray.bitarray(text)
                file.write(text_bits.tobytes())
                print(f"[*] Message : {text_bits.tobytes()}")
                # text_bits.tofile(file)
            elif isinstance(text, list):  # If ciphertext is a list of strings
                text_bits = bitarray.bitarray()
                for block in text:
                    text_bits.extend(bitarray.bitarray(block))
                file.write(text_bits.tobytes())
                print(f"[*] Message : {text_bits.tobytes()}")
            else:
                print("Bad Format.")
                return False

        print(f"Serpent output located at : {file_path}")
        return True
    except Exception as e:
        print(f"File Writing Error : {e}")
        return False

def masterkey_generation():
    master_key = hex(random.getrandbits(256))[2:].zfill(64)
    key_path = input("Path to key : ")
    try:
        with open(key_path, 'w') as file:
            file.write(master_key)
        print(f"Key [{master_key}] generated and stored at {key_path}")
        return master_key

    except FileNotFoundError:
        print(f"File not found : {key_path}")
        return None
    except Exception as e:
        print(f"Error : {e}")
        return None

def masterkey_file_read() :
    key_path = input("Path to key : ")
    master_key = ''
    try:
        with open(key_path, 'r') as file:
            master_key = file.read()
        print(f"Key [{master_key}] read at {key_path}")
        return master_key
    except FileNotFoundError:
        print(f"File not found : {key_path}")
    except Exception as e:
        print(f"Error : {e}")
"""------------------INPUT/OUTPUT FUNCTIONS---------------------------"""

"""------------------Front-end Menus----------------------------------"""
def front_encryption() :
    while True :
        choice = input("[1] - File encryption\n[2] - Message Encryption\n[3] - Cancel\n")
        match choice :
            case '1' :
                file_path = input("File path : ")
                message = read_file_convert(file_path)
                break
            case '2' :
                message = input_console_message()
                break
            case '3' | 'q' | 'quit' | 'exit':
                print('[+]  Exiting.....')
                sys.exit()
            case other :
                print("Wrong options")
    while True :
        key_choice = input("[1] - Key Generation\n[2] - Choose a key file\n[3] - Cancel\n")

        match key_choice :
            case '1' :
                master_key = masterkey_generation()
                cipher = encryption(message, master_key)
                output_to_file(cipher)
                break
            case '2' :
                master_key = masterkey_file_read()
                cipher = encryption(message, master_key)
                output_to_file(cipher)
                break
            case '3' | 'q' | 'quit' | 'exit':
                print('[+]  Exiting.....')
                sys.exit()
            case other :
                print("Choose a valid option")

def front_decryption() :
    file_path = input("File path : ")
    message = read_file_convert(file_path)
    master_key = master_key_file_read()
    PT = decryption(message, master_key)
    output_to_file(PT)
"""-----------------------Front-end Menus--------------------------------"""

"""-----------------------ENCRYPTION functions-----------------------------"""
def sbox_generation(sbox0) :
    buffer = copy.deepcopy(sbox0)
    sbox = []
    sbox.append(copy.deepcopy(sbox0))
    for i in range(1,32) :
        generate_sbox_permutation(buffer)
        sbox.append(copy.deepcopy(buffer))
    return sbox

def apply_sbox_to_block(sbox,data,key):
    #Bitwise XOR on the data block and the iteration key :
    block = int(data, 2) ^ int(key, 2) #String conversion (binary) to integers
    block = bin(block)[2:].zfill(128)
    # Division du bloc en mots de 4 bits
    assert len(block) == 128
    words_4_bits = [(block[i:i + 4]) for i in range(0, 128, 4)]

    #Apply Sbox on 4-bits words (word=index)
    sbox_results = [int(sbox[i][int(word, 2)]) for i, word in enumerate(words_4_bits)]
    for i in range(0,32) :
        sbox_results[i] = bin(sbox_results[i])[2:].zfill(4)

    #Concatenate the 4-bits words into 32-bits words
    result_words = [int(str(sbox_results[i])+str(sbox_results[i+1])+str(sbox_results[i+2])+str(sbox_results[i+3])+str(sbox_results[i+4])+str(sbox_results[i+5])+str(sbox_results[i+6])+str(sbox_results[i+7]),2) for i in range(0,31,8)]

    return result_words

def linear_transformation(sbox,block,key):
    X = [0]*4
    X[0],X[1],X[2],X[3] = apply_sbox_to_block(sbox,block,key)   #X[0],X[1],X[2],X[3] 4 32-bits words

    X[0] = circular_left_shift(X[0],13)
    X[2] = circular_left_shift(X[2],3)
    X[1] ^= X[0] ^ X[2]
    X[3] ^= X[2] ^ (X[0] << 3 & 0xFFFFFFFF)
    X[1] = circular_left_shift(X[1],1)
    X[3] = circular_left_shift(X[3],7)
    X[0] ^= X[1] ^ X[3]
    X[2] ^= X[3] ^ (X[1] << 7 & 0xFFFFFFFF)
    X[0] = circular_left_shift(X[0],5)
    X[2] = circular_left_shift(X[2],22)

    #print(X[0],X[1],X[2],X[3])
    X[0] = bin(X[0])[2:].zfill(32)
    X[1] = bin(X[1])[2:].zfill(32)
    X[2] = bin(X[2])[2:].zfill(32)
    X[3] = bin(X[3])[2:].zfill(32)

    block = ''.join(X)
    return block


def Last_Iteration(sbox,block,key) :
    X = [0]*4
    X[0], X[1], X[2], X[3] = apply_sbox_to_block(sbox,block, key[31])

    X[0] = bin(X[0])[2:].zfill(32)
    X[1] = bin(X[1])[2:].zfill(32)
    X[2] = bin(X[2])[2:].zfill(32)
    X[3] = bin(X[3])[2:].zfill(32)

    block = str(X[0] + X[1] + X[2] + X[3])
    block = int(block,2) ^ int(key[32],2)
    block = bin(block)[2:].zfill(128)
    return block

"""-------------------ENCRYPTION functions-------------------"""




"""-------------------DECRYPTION functions--------------------"""

def inverse_sbox_permutation() :
    inv_sbox = []
    buffer = copy.deepcopy(sbox0)
    inv_sbox.append(copy.deepcopy(sbox0))
    for i in range(1,32) :
        generate_sbox_permutation(buffer)
        inv_sbox.append(copy.deepcopy(buffer))
    inv_sbox = inv_sbox[::-1]
    return inv_sbox

def Reverse_Sbox_Application(data,inv_sbox) :

    words_4_bits = [(data[i:i + 4]) for i in range(0, 128, 4)]

    #Extract the index from the sbox applied to the cipher
    sbox_results = [int(inv_sbox[i].index(int(word, 2))) for i, word in enumerate(words_4_bits)]

    for i in range(0, 32):
        sbox_results[i] = bin(sbox_results[i])[2:].zfill(4)

    result_words = [str(sbox_results[i])+str(sbox_results[i+1])+str(sbox_results[i+2])+str(sbox_results[i+3])+str(sbox_results[i+4])+str(sbox_results[i+5])+str(sbox_results[i+6])+str(sbox_results[i+7]) for i in range(0,31,8)]
    return result_words

def reverse_last_iteration(cipher,round_keys,inv_sbox) :
    X = [0]*4
    cipher = int(cipher,2) ^ int(round_keys[0],2) # Cipher XOR last round key (reversed)
    cipher = str(bin(cipher)[2:].zfill(128))
    X[0], X[1], X[2], X[3] = Reverse_Sbox_Application(cipher, inv_sbox)

    cipher = str(X[0] + X[1] + X[2] + X[3])

    cipher = int(cipher,2) ^ int(round_keys[1],2) # Cipher XOR last round key (reversed)
    cipher = str(bin(cipher)[2:].zfill(128))
    return cipher


def inverse_linear_transformation(block,key,inv_sbox):

    X = [block[i:i + 32] for i in range(0, 128, 32)]
    for i in range(len(X)) :
        X[i] = int(X[i],2)

    X[2] = circular_right_shift(X[2], 22)
    X[0] = circular_right_shift(X[0], 5)
    X[2] ^= X[3] ^ (X[1] << 7 & 0xFFFFFFFF)
    X[0] ^= X[1] ^ X[3]
    X[3] = circular_right_shift(X[3], 7)
    X[1] = circular_right_shift(X[1], 1)
    X[3] ^= X[2] ^ (X[0] << 3 & 0xFFFFFFFF)
    X[1] ^= X[0] ^ X[2]
    X[2] = circular_right_shift(X[2], 3)
    X[0] = circular_right_shift(X[0], 13)

    X[0] = format(X[0],'032b')
    X[1] = format(X[1], '032b')
    X[2] = format(X[2], '032b')
    X[3] = format(X[3], '032b')
    block = ''.join(X)
    X[0], X[1], X[2], X[3] = Reverse_Sbox_Application(block, inv_sbox)


    block = str(X[0] + X[1] + X[2] + X[3])
    #Bitwise XOR on the data block and the iteration key :
    block = int(block, 2) ^ int(key, 2) #String conversion (binary) to integers
    block = bin(block)[2:].zfill(128)
    return block

"""-----------------------DECRYPTION Functions---------------------------"""



def encryption(data,master_key) :
    round_keys = generate_round_keys(master_key)
    sbox = sbox_generation(sbox0)

    if isinstance(data, list):  # If plaintext is a list of strings
        cipher = []
        for block in data :
            buffer = permutation_initiale(block)
            buffer = linear_transformation(sbox[0],buffer, round_keys[0])
            for i in range(1, 31):
                buffer = linear_transformation(sbox[i],buffer, round_keys[i])
            buffer = Last_Iteration(sbox[31],buffer, round_keys)
            buffer = permutation_finale(buffer)
            cipher.append(buffer)
    else :
        print("Plaintext format is not valid")
    return cipher


def decryption(cipher,master_key) :
    round_keys = generate_round_keys(master_key)
    round_keys.reverse()
    inv_sbox = inverse_sbox_permutation()

    if isinstance(cipher, list):  # If plaintext is a list of strings
        plaintext = []
        cipher.pop(-1) #Remove useless last block introduced by the file reading padding
        for block in cipher:
            buffer = permutation_initiale(block)
            buffer = reverse_last_iteration(buffer,round_keys,inv_sbox[0])
            for i in range(1, 32):
                buffer = inverse_linear_transformation(buffer, round_keys[i+1],inv_sbox[i])
            buffer = permutation_finale(buffer)
            plaintext.append(buffer)

        padding = (-1) * int(plaintext[-1],2)

        plaintext.pop(-1)
        PT = ''.join(plaintext)
        PT = PT[:padding]
        return PT
    else:
        print("Plaintext format is not valid")
    return cipher





