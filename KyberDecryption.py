from Crypto.Hash import SHA256, HMAC, SHAKE128
from Crypto.Protocol.KDF import PBKDF2
import random
import os
import zipfile
import datetime
from Crypto.Cipher import AES

n = 256  
q = 3329  
k = 2  

def generate_key():
    
    sk = [random.randint(0, q - 1) for _ in range(n * k)]
    pk = [random.randint(0, q - 1) for _ in range(n * k)]
    return sk, pk
    
def decapsulate(sk, ct):
    
    (u, t) = ct
    r_prime = [0] * n
    for i in range(k):
        for j in range(n):
            r_prime[j] += sk[i * n + j] * t[j]
            r_prime[j] %= q
    if r_prime == u:
        shared_secret = SHAKE128.new(bytes(t)).read(32)
        return shared_secret
    else:
        return None
        
def unlock_file(password):
    
    with open("KEY.enc", "rb") as encrypted_key_file:
        encrypted_data = encrypted_key_file.read()
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:16+16]
        tag = encrypted_data[16+16:16+16+16]
        ciphertext = encrypted_data[16+16+16:]

    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    try:
        decrypted_key_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print("Error: Incorrect password or corrupted data.")
        return

    sk, _ = generate_key()
    t = decapsulate(sk, (None, [decrypted_key_data[i] for i in range(len(decrypted_key_data))]))
    
    data = decrypted_key_data
    with open("KEY.txt", "wb") as key_file:
        key_file.write(decrypted_key_data)
    with open("LOGFILE", "r") as logfile:
        seq = [int(line.strip()) for line in logfile]
    
    original_data = b""
    with zipfile.ZipFile("SecuredFile.zip", "r") as secured_file:
        for i, chunk_number in enumerate(seq):
            chunk_name = f"chunk_{chunk_number}"
            secured_file.extract(chunk_name)
            with open(chunk_name, "rb") as chunk_file:
                chunk_data = chunk_file.read()
                original_data += chunk_data
            os.remove(chunk_name)
            
    with open("KEY.txt", "r") as key_file:
        metadata = {}
        for line in key_file:
            key, value = line.strip().split(": ",1)
            metadata[key.strip()] = value.strip()

    original_filename = metadata["Original filename"]
    original_extension = metadata["Original extension of the file"]
    restored_filename = f"{original_filename}"
    
    os.remove("LOGFILE")
    os.remove("LOGFILE_HASH")
    os.remove("KEY.enc")
    os.remove("KEY.txt")
    os.remove("SecuredFile.zip")

    with open(restored_filename, "wb") as original_file:
        original_file.write(original_data)

    print("Original file restored successfully.")
    
password = input("Enter the password to unlock the file: ")
unlock_file(password)
