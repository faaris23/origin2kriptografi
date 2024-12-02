import mysql.connector

# Koneksi ke Database
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",  
        database="db_penilangan"
    )

def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_data (
             id INT AUTO_INCREMENT PRIMARY KEY,
            image_data LONGBLOB,
            text_data TEXT,
            encrypted_text TEXT,
            encrypted_image LONGBLOB,
            algorithm VARCHAR(50),
            aes_key TEXT,
            vigenere_key TEXT,
            des_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

initialize_database()
