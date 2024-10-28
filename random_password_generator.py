import random
import string
import json
import os
import datetime
import csv
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, filedialog

# Generate or load encryption key
KEY_FILE = 'key.key'
DATA_FILE = 'passwords.json'
EXPIRATION_DAYS = 90  # Set password expiration period

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return key

fernet = Fernet(load_key())

# Password Generation
def generate_password(length=12, include_upper=True, include_lower=True, include_digits=True, include_symbols=True):
    char_set = ''
    if include_upper:
        char_set += string.ascii_uppercase
    if include_lower:
        char_set += string.ascii_lowercase
    if include_digits:
        char_set += string.digits
    if include_symbols:
        char_set += string.punctuation

    if not char_set:
        raise ValueError("At least one character type must be selected")

    password = ''.join(random.choice(char_set) for _ in range(length))
    return password

# Password Strength Checker
def check_password_strength(password):
    length_score = min(10, len(password))
    diversity_score = len(set(password))
    strength_score = length_score + diversity_score

    if strength_score > 15:
        return "Strong"
    elif strength_score > 10:
        return "Medium"
    else:
        return "Weak"

# Check for Reused Password
def is_password_reused(password):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            data = json.load(file)
        for account in data.values():
            if fernet.decrypt(account['password'].encode()).decode() == password:
                return True
    return False

# Save Password with Encryption
def save_password(account, password):
    encrypted_password = fernet.encrypt(password.encode()).decode()
    expiration_date = (datetime.datetime.now() + datetime.timedelta(days=EXPIRATION_DAYS)).isoformat()

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            data = json.load(file)
    else:
        data = {}

    data[account] = {'password': encrypted_password, 'expiration': expiration_date}

    with open(DATA_FILE, 'w') as file:
        json.dump(data, file)

# Retrieve Password
def retrieve_password(account):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            data = json.load(file)
        if account in data:
            encrypted_password = data[account]['password']
            expiration_date = data[account]['expiration']
            decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
            return decrypted_password, expiration_date
    return None, None

# Export Passwords to CSV
def export_passwords():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            data = json.load(file)
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            with open(file_path, 'w', newline='') as csvfile:
                fieldnames = ['Account', 'Password', 'Expiration Date']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for account, info in data.items():
                    decrypted_password = fernet.decrypt(info['password'].encode()).decode()
                    writer.writerow({'Account': account, 'Password': decrypted_password, 'Expiration Date': info['expiration']})
            messagebox.showinfo("Export Success", "Passwords exported successfully.")
    else:
        messagebox.showerror("Export Error", "No passwords to export.")

# GUI Setup
class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")

        # GUI Elements
        tk.Label(root, text="Account").grid(row=0, column=0, padx=10, pady=5)
        tk.Label(root, text="Length").grid(row=1, column=0, padx=10, pady=5)
        self.account_entry = tk.Entry(root)
        self.account_entry.grid(row=0, column=1)

        self.length_entry = tk.Entry(root)
        self.length_entry.insert(0, "12")
        self.length_entry.grid(row=1, column=1)

        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        
        tk.Checkbutton(root, text="Uppercase", variable=self.upper_var).grid(row=2, column=0, sticky="w")
        tk.Checkbutton(root, text="Lowercase", variable=self.lower_var).grid(row=2, column=1, sticky="w")
        tk.Checkbutton(root, text="Digits", variable=self.digits_var).grid(row=3, column=0, sticky="w")
        tk.Checkbutton(root, text="Symbols", variable=self.symbols_var).grid(row=3, column=1, sticky="w")
        
        self.generate_button = tk.Button(root, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.save_button = tk.Button(root, text="Save Password", command=self.save_password)
        self.save_button.grid(row=5, column=0, columnspan=2, pady=5)

        self.export_button = tk.Button(root, text="Export to CSV", command=export_passwords)
        self.export_button.grid(row=6, column=0, columnspan=2, pady=5)

        self.password_display = tk.Label(root, text="", font=("Arial", 12), wraplength=250)
        self.password_display.grid(row=7, column=0, columnspan=2, pady=10)

    def generate_password(self):
        length = int(self.length_entry.get())
        include_upper = self.upper_var.get()
        include_lower = self.lower_var.get()
        include_digits = self.digits_var.get()
        include_symbols = self.symbols_var.get()

        password = generate_password(length, include_upper, include_lower, include_digits, include_symbols)
        
        if is_password_reused(password):
            self.password_display.config(text="Password is reused, try regenerating!")
        else:
            self.password_display.config(text=f"Generated Password: {password}\nStrength: {check_password_strength(password)}")

    def save_password(self):
        account = self.account_entry.get()
        password_text = self.password_display.cget("text").split("Generated Password: ")[-1].split("\n")[0]

        if account and password_text:
            save_password(account, password_text)
            messagebox.showinfo("Save Success", f"Password for '{account}' saved successfully.")
        else:
            messagebox.showerror("Save Error", "Please provide an account name and generate a password first.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
