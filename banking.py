import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3
import base64

# Database setup
DB_NAME = "banking_system.db"

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            account_number INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            balance REAL NOT NULL,
            pin TEXT NOT NULL,
            encryption_key TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Encryption utilities
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

# Core banking functions
def create_account(name, pin):
    key = get_random_bytes(16)  # Generate encryption key
    encrypted_pin = encrypt_data(pin, key)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (name, balance, pin, encryption_key)
        VALUES (?, ?, ?, ?)
    """, (name, 0.0, encrypted_pin, base64.b64encode(key).decode()))
    conn.commit()
    account_number = cursor.lastmod
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

# UI Setup
class BankingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Banking Simulator")
        self.root.geometry("500x400")
        
        # Home Page
        self.home_frame = tk.Frame(self.root)
        self.home_frame.pack(fill="both", expand=True)
        tk.Label(self.home_frame, text="Welcome to Secure Banking Simulator", font=("Arial", 16)).pack(pad=20)
        tk.Button(self.home_frame, text="Create Account", command=self.create_account_page, width=20).pack(pad=10)
        tk.Button(self.home_frame, text="Login", command=self.login_page, width=20).pack(pad=10)
        tk.Button(self.home_frame, text="Exit", command=self.root.quit, width=20).pack(pad=10)

        # Account Creation Page
        self.account_creation_frame = tk.Frame(self.root)
        tk.Label(self.account_creation_frame, text="Create New Account", font=("Arial", 16)).pack(pad=10)
        tk.Label(self.account_creation_frame, text="Name:").pack()
        self.name_entry = tk.Entry(self.account_creation_frame)
        self.name_entry.pack()
        tk.Label(self.account_creation_frame, text="PIN (4 digits):").pack()
        self.pin_entry = tk.Entry(self.account_creation_frame, show="*")
        self.pin_entry.pack()
        tk.Button(self.account_creation_frame, text="Create Account", command=self.create_account).pack(pad=10)
        tk.Button(self.account_creation_frame, text="Back", command=self.show_home_page).pack()

        # Login Page
        self.login_frame = tk.Frame(self.root)
        tk.Label(self.login_frame, text="Login", font=("Arial", 16)).pack(pad=10)
        tk.Label(self.login_frame, text="Account Number:").pack()
        self.account_entry = tk.Entry(self.login_frame)
        self.account_entry.pack()
        tk.Label(self.login_frame, text="PIN:").pack()
        self.login_pin_entry = tk.Entry(self.login_frame, show="*")
        self.login_pin_entry.pack()
        tk.Button(self.login_frame, text="Login", command=self.login).pack(pad=10)
        tk.Button(self.login_frame, text="Back", command=self.show_home_page).pack()

    def show_home_page(self):
        self.account_creation_frame.pack_forget()
        self.login_frame.pack_forget()
        self.home_frame.pack(fill="both", expand=True)

    def create_account_page(self):
        self.home_frame.pack_forget()
        self.account_creation_frame.pack(fill="both", expand=True)

    def login_page(self):
        self.home_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def create_account(self):
        name = self.name_entry.get()
        pin = self.pin_entry.get()
        if len(pin) != 4 or not pin.isdigit():
            messagebox.showerror("Error", "PIN must be 4 digits!")
            return
        account_number = create_account(name, pin)
        messagebox.showinfo("Success", f"Account created successfully! Your account number is {account_number}")
        self.show_home_page()

    def login(self):
        account_number = self.account_entry.get()
        pin = self.login_pin_entry.get()
        if not account_number.isdigit() or not pin.isdigit():
            messagebox.showerror("Error", "Invalid account number or PIN!")
            return
        if authenticate_user(int(account_number), pin):
            messagebox.showinfo("Success", "Login successful!")
            # Here you can redirect to a dashboard or other operations
        else:
            messagebox.showerror("Error", "Authentication failed!")

# Main application
if __name__ == "__main__":
    initialize_database()
    root = tk.Tk()
    app = BankingApp(root)
    root.mainloop()
