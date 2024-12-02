import os
import hashlib
import secrets
import string
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Generate a random AES key
def generate_aes_key():
    return os.urandom(16)  # 16 bytes for AES-128

# AES encryption
def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text, AES.block_size))
    return cipher.iv + ct_bytes  # Return IV + ciphertext

# AES decryption
def aes_decrypt(encrypted_text, key):
    iv = encrypted_text[:16]  # Extract IV
    ciphertext = encrypted_text[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_text

# Vigenère encryption
def vigenere_encrypt(text, key):
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    text_as_int = [ord(i) for i in text]
    ciphertext = ''
    for i in range(len(text_as_int)):
        value = (text_as_int[i] + key_as_int[i % key_length]) % 256
        ciphertext += chr(value)
    return ciphertext

# Vigenère decryption
def vigenere_decrypt(encrypted_text, key):
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    text_as_int = [ord(i) for i in encrypted_text]
    plaintext = ''
    for i in range(len(text_as_int)):
        value = (text_as_int[i] - key_as_int[i % key_length]) % 256
        plaintext += chr(value)
    return plaintext

# Hashing function
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Generate a random key for Vigenère cipher
def generate_vigenere_key(length=8):
    return ''.join(secrets.choice(string.ascii_letters) for _ in range(length))

# Generate a random DES key
def generate_des_key():
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))

# DES encryption
def des_encrypt(text, key):
    if isinstance(text, str):
        data_to_encrypt = text.encode()
    else:
        data_to_encrypt = text
    cipher = DES.new(key.encode(), DES.MODE_CBC)
    encrypted_text = cipher.encrypt(pad(data_to_encrypt, DES.block_size))
    return cipher.iv + encrypted_text  # Return IV + ciphertext

# DES decryption
def des_decrypt(encrypted_text, key):
    iv = encrypted_text[:8]  # Extract IV
    ciphertext = encrypted_text[8:]
    cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_text.decode()