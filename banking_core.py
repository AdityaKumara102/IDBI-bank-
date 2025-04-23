import sqlite3
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

DB_NAME = "banking_system.db"

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            account_number INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            balance REAL NOT NULL,
            pin TEXT NOT NULL,
            encryption_key TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphered, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + ciphered).decode()

def decrypt_data(encrypted_data, key):
    raw_data = base64.b64decode(encrypted_data)
    nonce = raw_data[:16]
    ciphered = raw_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphered).decode()

def create_account(name, pin):
    key = get_random_bytes(16)
    encrypted_pin = encrypt_data(pin, key)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (name, balance, pin, encryption_key)
        VALUES (?, ?, ?, ?)
    """, (name, 0.0, encrypted_pin, base64.b64encode(key).decode()))
    conn.commit()
    account_number = cursor.lastrowid
    conn.close()
    return account_number

def authenticate_user(account_number, pin):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT pin, encryption_key FROM users WHERE account_number=?", (account_number,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return False
    encrypted_pin, key = user
    key = base64.b64decode(key)
    decrypted_pin = decrypt_data(encrypted_pin, key)
    return decrypted_pin == pin

def perform_transaction(account_number, amount, transaction_type):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE account_number=?", (account_number,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return None
    current_balance = user[0]
    if transaction_type == "withdrawal" and amount > current_balance:
        conn.close()
        return None
    new_balance = current_balance + amount if transaction_type == "deposit" else current_balance - amount
    cursor.execute("UPDATE users SET balance=? WHERE account_number=?", (new_balance, account_number))
    conn.commit()
    conn.close()
    return new_balance

def get_balance(account_number):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE account_number=?", (account_number,))
    user = cursor.fetchone()
    conn.close()
    return user[0] if user else None
