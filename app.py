
from Crypto.Cipher import DES
import pytesseract
from PIL import Image
import streamlit as st
from auth import login_user, register_user
from encryption import extract_text_from_image, encrypt_text, encrypt_image, save_encrypted_data, decrypt_text
from db_config import get_db_connection
import base64
from io import BytesIO
from PIL import Image
from encryption_utils import (
    hash_text,
    des_encrypt,
    des_decrypt,
    generate_des_key,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    generate_vigenere_key,
    vigenere_encrypt,
    vigenere_decrypt,
)
import hashlib
import secrets
import string

from Crypto.Cipher import DES
import pytesseract
from PIL import Image

# Fungsi untuk enkripsi DES
def des_encrypt(data, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    while len(data) % 8 != 0:
        data += b' '
    encrypted_data = cipher.encrypt(data)
    return encrypted_data.hex()  # Mengembalikan dalam format hex untuk representasi yang lebih baik

# Fungsi untuk dekripsi DES
def des_decrypt(encrypted_data, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted_data = cipher.decrypt(bytes.fromhex(encrypted_data))
    return decrypted_data.strip()

# Fungsi untuk ekstraksi teks dari gambar
def extract_text_from_image(image):
    return pytesseract.image_to_string(image)

# Fungsi untuk enkripsi Vigenere
def vigenere_encrypt(text, key):
    encrypted_text = []
    key_length = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % key_length].lower()) - ord('a')
            new_char = chr(((ord(char.lower()) - ord('a') + shift) % 26) + ord('a'))
            encrypted_text.append(new_char if char.islower() else new_char.upper())
        else:
            encrypted_text.append(char)
    return ''.join(encrypted_text)

# Fungsi untuk dekripsi Vigenere
def vigenere_decrypt(text, key):
    decrypted_text = []
    key_length = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            shift = -(ord(key[i % key_length].lower()) - ord('a'))
            new_char = chr(((ord(char.lower()) - ord('a') + shift) % 26) + ord('a'))
            decrypted_text.append(new_char if char.islower() else new_char.upper())
        else:
            decrypted_text.append(char)
    return ''.join(decrypted_text)

# Fungsi untuk enkripsi Caesar
def caesar_encrypt(text, shift):
    encrypted_text = []
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a')) if char.islower() else chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
            encrypted_text.append(new_char)
        else:
            encrypted_text.append(char)
    return ''.join(encrypted_text)

# Fungsi untuk dekripsi Caesar
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Fungsi untuk Super Encryption
def super_encrypt(text, vigenere_key, caesar_shift):
    vigenere_encrypted = vigenere_encrypt(text, vigenere_key)
    caesar_encrypted = caesar_encrypt(vigenere_encrypted, caesar_shift)
    return caesar_encrypted

# Fungsi untuk Super Decryption
def super_decrypt(text, vigenere_key, caesar_shift):
    caesar_decrypted = caesar_decrypt(text, caesar_shift)  # Reverse Caesar shift
    vigenere_decrypted = vigenere_decrypt(caesar_decrypted, vigenere_key)  # Reverse Vigenere
    return vigenere_decrypted
st.title("SISTEM PENNYIMPANAN HASIL EKSTRAKSI TEKS DARI GAMBAR")

menu = st.sidebar.selectbox("Menu", ["Login", "Register", "Enkripsi", "Dekripsi", "Lihat Data"])

if menu == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login_user(username, password):
            st.success("Login berhasil!")
            st.session_state["authenticated"] = True
        else:
            st.error("Username atau password salah!")

elif menu == "Register":
    st.subheader("Register")
    username = st.text_input("Username")
    password = st .text_input("Password", type="password")
    if st.button("Register"):
        if register_user(username, password):
            st.success("Pendaftaran berhasil!")
        else:
            st.error("Username sudah ada!")

if menu == "Enkripsi":
    if st.session_state.get("authenticated"):
        st.subheader("Enkripsi")
        algorithm = st.selectbox("Pilih algoritma enkripsi", ["Pilih", "DES", "Hash", "Super Enkripsi"])

        if algorithm != "Pilih":
            uploaded_file = st.file_uploader("Upload gambar", type=["png", "jpg", "jpeg"])

            if uploaded_file:
                image = Image.open(uploaded_file)
                st.image(image, caption="Gambar diunggah", use_column_width=True)

                extracted_text = extract_text_from_image(image)
                if isinstance(extracted_text, bytes):  # Jika bytes, ubah ke string
                    extracted_text = extracted_text.decode()
                st.write("Teks yang diambil dari gambar:", extracted_text)

                if st.button("Lakukan Enkripsi"):
                    try:
                        if algorithm == "DES":
                            des_key = generate_des_key()
                            encrypted_text = des_encrypt(extracted_text, des_key)
                            st.write("Teks terenkripsi (DES):", encrypted_text.decode('latin-1'))  # Ubah bytes ke string untuk tampilan
                            st.write("Kunci DES yang dihasilkan:", des_key)

                        elif algorithm == "Hash":
                            encrypted_text = hash_text(extracted_text)
                            st.write("Teks terenkripsi (Hash):", encrypted_text)

                        elif algorithm == "Super Enkripsi":
                            aes_key = generate_aes_key()
                            vigenere_key = generate_vigenere_key()
                            encrypted_text = super_encrypt(extracted_text, aes_key, vigenere_key)
                            st.write("Teks terenkripsi (Super Enkripsi):", encrypted_text)
                            st.write("Kunci AES yang dihasilkan:", aes_key)
                            st.write("Kunci Vigenère yang dihasilkan:", vigenere_key)

                        save_encrypted_data(
                            uploaded_file.getvalue(),
                            extracted_text,
                            encrypted_text,
                            None,
                            aes_key if algorithm == "Super Enkripsi" else None,
                            vigenere_key if algorithm == "Super Enkripsi" else None,
                            des_key if algorithm == "DES" else None
                        )
                        st.success("Data berhasil dienkripsi dan disimpan.")
                    except Exception as e:
                        st.error(f"Kesalahan dalam enkripsi: {e}")
            else:
                st.warning("Silakan unggah gambar terlebih dahulu!")
        else:
            st.warning("Silakan pilih algoritma enkripsi!")
    else:
        st.warning("Silakan login terlebih dahulu!")

elif menu == "Dekripsi":
    if st.session_state.get("authenticated"):
        st.subheader("Dekripsi")

        # Ambil data dari database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, encrypted_text, algorithm, aes_key, vigenere_key, des_key FROM encrypted_data")
        data = cursor.fetchall()
        conn.close()

        if data:
            # Pilih ID data yang akan didekripsi
            selected_id = st.selectbox("Pilih ID untuk dekripsi", [row[0] for row in data])
            selected_row = next(row for row in data if row[0] == selected_id)

            encrypted_text = selected_row[1]
            algorithm = selected_row[2]
            aes_key = selected_row[3]
            vigenere_key = selected_row[4]
            des_key = selected_row[5]

            st.write("Algoritma enkripsi data:", algorithm)

            # Dekripsi berdasarkan algoritma yang digunakan
            if st.button("Dekripsi"):
                try:
                    if algorithm == "DES":
                        decrypted_text = des_decrypt(encrypted_text, des_key)
                    elif algorithm == "Hash":
                        decrypted_text = "Hash tidak dapat didekripsi."
                    elif algorithm == "Super Enkripsi":
                        decrypted_text = super_decrypt(encrypted_text, aes_key, vigenere_key)

                    st.write("Teks yang didekripsi:", decrypted_text)
                except Exception as e:
                    st.error(f"Kesalahan dalam dekripsi: {e}")
        else:
            st.warning("Tidak ada data terenkripsi.")
    else:
        st.warning("Silakan login terlebih dahulu!")

elif menu == "Lihat Data":
    if st.session_state.get("authenticated"):
        st.subheader("Data Terenkripsi")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, text_data, encrypted_text, date FROM encrypted_data")
        data = cursor.fetchall()
        conn.close()

        if data:
            st.write (data)
        else:
            st.warning("Tidak ada data di database.")
    else:
        st.warning("Silakan login terlebih dahulu!")