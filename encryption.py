from cryptography.fernet import Fernet
import pytesseract
import base64
from io import BytesIO
from PIL import Image
from db_config import get_db_connection

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

#Generate Fernet Key
FERNET_KEY_FILE = "fernet_key.key"

def load_or_generate_key():
    try:
        with open(FERNET_KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

FERNET_KEY = load_or_generate_key()
cipher_suite = Fernet(FERNET_KEY)


def extract_text_from_image(image):
    return pytesseract.image_to_string(image)


def encrypt_text(text):
    return cipher_suite.encrypt(text.encode()).decode()


def encrypt_image(image):
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()


def save_encrypted_data(image, extracted_text, encrypted_text, encrypted_image):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO encrypted_data (image, text, encrypted_text, encrypted_image) VALUES (%s, %s, %s, %s)",
        (image, extracted_text, encrypted_text, encrypted_image)
    )
    conn.commit()
    conn.close()

def decrypt_text(encrypted_text):
    return cipher_suite.decrypt(encrypted_text.encode()).decode()
