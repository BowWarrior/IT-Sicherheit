import random
import hashlib
import struct
import os
from Crypto.Cipher import AES

possible_chars = "1234567890"
char_list = list(possible_chars)
password_length = 4
password = "9752"
dirname = os.path.dirname(__file__)
file_path = os.path.join(dirname, "databases", "Abbes.kdbx")

def brute_force_password():
    myguess = ""
    counter = 0
    while (myguess != password):
        #print(k=len(password))
        myguess = random.choices(char_list, k=password_length)
        counter += 1
        #print(myguess)
        myguess = "".join(myguess)
    print("You cracked the password! It was " + myguess + " and it took " + str(counter) + " tries.")

#brute_force_password()

def get_keypass_header(file_path):
    with open(file_path, "rb") as file:
        signature1 = struct.unpack("<4s", file.read(4))[0]
        signature2 = struct.unpack("<4s", file.read(4))[0]
        version = struct.unpack("<4s", file.read(4))[0]
        
        header_fields = {}

        #print(f"Signature 1: {signature1.hex()}")
        #print(f"Signature 2: {signature2.hex()}")
        #print(f"Version: {version.hex()}")

        if signature1.hex() != '03d9a29a' or signature2.hex() != '67fb4bb5':
            raise ValueError("Invalid Keypass file format")
        
        while True:
            '''
            ID:            Description:
            00             end of header (encrypted db starts after this field)
            04             master seed (32 bytes)
            05             transform seed (32 bytes)
            06             transform rounds (8 bytes)
            07             encryption initialisation vector (IV)
            09             stream start bytes (the first 32 bytes of the decrypted database)            

            '''
            field_id = ord(file.read(1))
            if field_id == 0:
                #print("header ended")
                break
            field_len = struct.unpack("<H", file.read(2))[0]
            data = file.read(field_len)
            header_fields[field_id] = data
            
            #print(f"data: {data.hex()}")
            #print(f"Field {field_id:02X} ({field_len} bytes)")
        return header_fields
    
def return_master_seed(header_fields):
    seed = header_fields[0x04]
    if len(seed) != 32:
        raise ValueError("Master seed should be 32 bytes.")
    return seed

def return_transform_seed(header_fields):
    seed = header_fields[0x05]
    if len(seed) != 32:
        raise ValueError("Transform seed should be 32 bytes.")
    return seed

def return_transform_round(header_fields):
    seed = header_fields[0x06]
    if len(seed) != 8:
        raise ValueError("Transform round should be 8 bytes.")
    return struct.unpack("<Q", seed)[0]  #converts bytes to int

def return_initialization_vector(header_fields):
    seed = header_fields[0x07]
    if len(seed) != 16:
        raise ValueError("Transform seed should be 16 bytes.")
    return seed
    
def return_stream_start_bytes(header_fields):
    seed = header_fields[0x09]
    if len(seed) != 32:
        raise ValueError("Transform seed should be 32 bytes.")
    return seed


def aes_encrypt(data, key, rounds):
    cipher = AES.new(key, AES.MODE_ECB)
    for _ in range(rounds):
        data = cipher.encrypt(data)
    return data


def return_hashed_password(guess, header_fields):
    #hashed twice because that's the format of the password for the DB

    credentials = hashlib.sha256(hashlib.sha256(guess.encode()).digest()).digest()
    transformed_credentials = hashlib.sha256(aes_encrypt(credentials, return_transform_seed(header_fields), return_transform_round(header_fields))).digest()
    key = hashlib.sha256(return_master_seed(header_fields) + transformed_credentials).digest()
    return key

def im_in_the_mainframe():
    hashed_password = return_stream_start_bytes(header_fields) # this is where the stream starts, so we want to decrypt this
    guess = ''
    correct_answer = ''
    counter = 0
    while (correct_answer != hashed_password):
        guess = random.choices(char_list, k=password_length)
        guess = "".join(guess)
        
        correct_answer = return_hashed_password(guess, header_fields)
        if correct_answer == hashed_password:
            print(f"Password cracked: {guess} in {counter} tries")
            return guess
        counter += 1

        if(counter > 9999):
            print("it's not a 4 digit number")
            return None
        
    print(f"Password cracked: {guess} in {counter} tries")
    return guess



#get_keypass_header(file_path)
#return_master_seed(get_keypass_header(file_path))



header_fields = get_keypass_header(file_path)
'''
master_seed = return_master_seed(header_fields)
print(f"Master seed: {master_seed.hex()}")

transform_seed = return_transform_seed(header_fields)
print(f"Transform seed: {transform_seed.hex()}")

transform_round = return_transform_round(header_fields)
print(f"Transform round: {transform_round.hex()}")

initialization_vector = return_initialization_vector(header_fields)
print(f"Initialization vector: {initialization_vector.hex()}")
'''
stream_start_bytes = return_stream_start_bytes(header_fields)
print(f"Stream start bytes: {stream_start_bytes.hex()}")



answer = im_in_the_mainframe()