from Crypto.Hash import SHA256, HMAC, SHAKE128
from Crypto.Protocol.KDF import PBKDF2
import random
import time
import os
import zipfile
import datetime
from Crypto.Cipher import AES

n = 256  
q = 3329  
k = 2 

def random_size_generation(file_size):
    result = []
    stability_variable = 0.5

    while file_size > 0:
        n = random.randint(1, int(file_size ** stability_variable))
        result.append(n)
        file_size -= n
        
    return result

def generate_key():
    sk = [random.randint(0, q - 1) for _ in range(n * k)]
    pk = [random.randint(0, q - 1) for _ in range(n * k)]
    return sk, pk

def encapsulate(pk):
    r = [random.randint(0, q - 1) for _ in range(n)]
    t = [0] * n
    for j in range(n):
        t[j] = sum(pk[i * n + j] * r[j] % q for i in range(k)) % q
    return r, t

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

def store_KEY(meta_data, password):
    with open("KEY.txt", "w") as key_file:
        for key, value in meta_data.items():
            key_file.write(f"{key}: {value}\n")

    with open("KEY.txt", "rb") as key_file:
        key_data = key_file.read()

    salt = os.urandom(16)  
    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)  
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(key_data)

    with open("KEY.enc", "wb") as encrypted_key_file:
        encrypted_key_file.write(salt)  
        encrypted_key_file.write(cipher.nonce)  
        encrypted_key_file.write(tag)  
        encrypted_key_file.write(ciphertext)  

    print("Encrypted KEY file stored successfully.")

def secure_file(file_path, password):
    size = os.path.getsize(file_path)
    
    nsize = random_size_generation(size)

    seq = random.sample(range(1, len(nsize) + 1), len(nsize))
    
    for i in range(len(seq)):
        with open(file_path, "rb") as input_file:
            input_file.seek(sum(nsize[:i]))
            chunk_data = input_file.read(nsize[i])

        with open(f"chunk_{seq[i]}", "wb") as chunk_file:
            chunk_file.write(chunk_data)
            with open("LOGFILE", "a") as logfile:
                logfile.write(f"{seq[i]}\n")

    with open("LOGFILE", "r") as logfile:
        logfile_content = logfile.read()

    with open("LOGFILE", "rb") as logfile:
        logfile_data = logfile.read()
        logfile_hash = SHA256.new(logfile_data).hexdigest()

    key_for_logfile = os.urandom(32)  # Generating a random key for the LOGFILE
    cipher_for_logfile = AES.new(key_for_logfile, AES.MODE_EAX)
    with open("LOGFILE", "rb") as logfile:
        logfile_data = logfile.read()
        ciphertext_for_logfile, tag_for_logfile = cipher_for_logfile.encrypt_and_digest(logfile_data)
    with open("LOGFILE.enc", "wb") as encrypted_logfile:
        encrypted_logfile.write(cipher_for_logfile.nonce + tag_for_logfile + ciphertext_for_logfile)

    key_for_logfile, pk = generate_key()  
    r, t = encapsulate(pk)

    t_bytes = bytes(t[i] % 256 for i in range(n))

    with open("KEY.enc", "wb") as encrypted_key_file:
        encrypted_key_file.write(t_bytes)

    with open("LOGFILE_HASH", "w") as logfile_hash_file:
        logfile_hash_file.write(logfile_hash)

    with zipfile.ZipFile("SecuredFile.zip", "w") as secured_file:
        for i in range(1,len(nsize) + 1):
            secured_file.write(f"chunk_{i}")

    for i in range(1,len(nsize) + 1):
        os.remove(f"chunk_{i}")

    file_path1 = "LOGFILE"
    _, extension = os.path.splitext(file_path1)
    metadata = {
            'File Size (bytes)': os.path.getsize(file_path1),
            'Creation Time': datetime.datetime.fromtimestamp(os.path.getctime(file_path1)),
            'Access Time': datetime.datetime.fromtimestamp(os.path.getatime(file_path1)),
            'Permissions': oct(os.stat(file_path1).st_mode)[-3:],
            'Extension': extension
        }

    meta_data = {"Original filename": os.path.basename(file_path),
                 "Original extension of the file": os.path.splitext(file_path)[1],
                 "LOGFILE information": metadata,
                 "Hash of the LOGFILE": logfile_hash }
    store_KEY(meta_data, password)
    print("File secured successfully.")

    os.remove(file_path)
    os.remove("LOGFILE_HASH")
    os.remove("KEY.txt")

file_to_secure = input("Enter the path of the file to secure: ")
password = input("Enter the password: ")
secure_file(file_to_secure, password)
