import random
import string
import json
import os
import datetime
from cryptography.fernet import Fernet
import argparse

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

# Check Expiration
def check_expiration(account):
    password, expiration = retrieve_password(account)
    if expiration:
        expiration_date = datetime.datetime.fromisoformat(expiration)
        if expiration_date < datetime.datetime.now():
            print(f"[ALERT] Password for {account} has expired! Consider updating.")
        else:
            print(f"Password for {account} is valid until {expiration_date.strftime('%Y-%m-%d')}")
    else:
        print(f"No expiration found for account: {account}")

# Command-line Interface
def main():
    parser = argparse.ArgumentParser(description="Secure Password Generator with Strength Checker and Expiration Reminder")
    parser.add_argument("-g", "--generate", help="Generate a new password", action="store_true")
    parser.add_argument("-l", "--length", type=int, default=12, help="Password length")
    parser.add_argument("-a", "--account", type=str, help="Account name for storing/retrieving password")
    parser.add_argument("--no-upper", action="store_false", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_false", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_false", help="Exclude digits")
    parser.add_argument("--no-symbols", action="store_false", help="Exclude symbols")
    parser.add_argument("-r", "--retrieve", help="Retrieve an existing password", action="store_true")
    parser.add_argument("-c", "--check", help="Check password expiration", action="store_true")

    args = parser.parse_args()

    if args.generate:
        try:
            password = generate_password(
                length=args.length,
                include_upper=args.no_upper,
                include_lower=args.no_lower,
                include_digits=args.no_digits,
                include_symbols=args.no_symbols,
            )
            print(f"Generated Password: {password}")
            print("Strength:", check_password_strength(password))

            if args.account:
                save_password(args.account, password)
                print(f"Password saved for account: {args.account}")

        except ValueError as e:
            print(e)

    elif args.retrieve:
        if args.account:
            password, expiration = retrieve_password(args.account)
            if password:
                print(f"Password for {args.account}: {password}")
                print(f"Expires on: {expiration}")
            else:
                print("Account not found")

    elif args.check:
        if args.account:
            check_expiration(args.account)
        else:
            print("Please specify an account to check expiration")

if __name__ == "__main__":
    main()
