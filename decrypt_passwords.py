import subprocess
import os
import sqlite3
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# see https://source.chromium.org/chromium/chromium/src/+/main:components/os_crypt/sync/os_crypt_linux.cc
SALT = b'saltysalt'
IV = b' ' * 16
LENGTH = 16
KEY_ITERATIONS = 1

def clean(decrypted):
    """remove padding from decrypted password"""
    if decrypted:
        # remove padding
        padding_length = decrypted[-1]
        if padding_length <= 16:
            return decrypted[:-padding_length].decode('utf-8', errors='ignore')
    if decrypted:
        return decrypted.decode('utf-8', errors='ignore')
    else:
        return ""

def decrypt_password(encrypted_password_hex, secret):
    """decrypt Chrome/Chromium password"""
    if not encrypted_password_hex or encrypted_password_hex == "":
        return ""
    
    try:
        # convert hex string to bytes
        encrypted_data = bytes.fromhex(encrypted_password_hex)
        
        # check for v10/v11 prefix (3 bytes: b'v10' or b'v11')
        if len(encrypted_data) >= 3:
            prefix = encrypted_data[:3]
            if prefix == b'v10' or prefix == b'v11':
                # for v10, the hardcoded key is "peanuts"
                # see Chromium's os_crypt_linux.cc
                if prefix == b'v10':
                    secret = "peanuts"
                
                # Remove the prefix
                encrypted_data = encrypted_data[3:]
        
        # generate key
        key = PBKDF2(secret.encode('utf-8'), SALT, LENGTH, KEY_ITERATIONS)
        
        # decrypt
        cipher = AES.new(key, AES.MODE_CBC, IV=IV)
        decrypted = cipher.decrypt(encrypted_data)
        
        return clean(decrypted)
    except Exception as e:
        return f"[Decryption Error: {e}]"

def get_passwords_from_db(browser, secret):
    """get and decrypt passwords from browser's SQLite database"""
    if browser == "chromium":
        db_path = f'/home/{os.getlogin()}/.config/chromium/Default/Login Data'
    elif browser == "chrome":
        db_path = f'/home/{os.getlogin()}/.config/google-chrome/Default/Login Data'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, hex(password_value) FROM logins;')
        rows = cursor.fetchall()
        conn.close()
        
        # decrypt each password
        decrypted_rows = []
        for url, username, encrypted_hex in rows:
            decrypted_password = decrypt_password(encrypted_hex, secret)
            decrypted_rows.append((url, username, decrypted_password))
        
        return decrypted_rows

    except Exception as e:
        return f"Error accessing {browser}'s database: {e}"

# find which browsers have keyring passwords
browsers = {}
for name in ["chromium", "chrome"]:
    try:
        pwd = subprocess.check_output(["secret-tool", "lookup", "application", name], 
                                     text=True, stderr=subprocess.DEVNULL).strip()
        browsers[name] = pwd
    except:
        pass

if not browsers:
    print("No passwords found in keyring, for Chrome nor Chromium")
    exit()

elif len(browsers) == 1:
    browser, secret = list(browsers.items())[0]
    print(f"Going for {browser} (only one found)")
    print(f"Keyring secret: {secret}")
    print("\nFetching and decrypting saved passwords from database...")
    
    # get and decrypt passwords
    passwords = get_passwords_from_db(browser, secret)
    
    # display results
    if isinstance(passwords, str):  # error message
        print(passwords)
    else:
        print(f"\nFound {len(passwords)} saved passwords:")
        print("=" * 80)
        for url, username, password in passwords:
            print(f"URL: {url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print("-" * 40)

else:
    # multiple browsers found, ask user
    items = list(browsers.items())
    print("Multiple browsers found in keyring:")
    
    for i, (browser, _) in enumerate(items, 1):
        print(f"{i}. {browser}")
    
    try:
        choice = int(input(f"\nPick browser (1-{len(items)}): ")) - 1
        selected_browser, secret = items[choice]
        
        print(f"\nSelected {selected_browser}")
        print(f"Keyring secret: {secret}")
        
        print("\nFetching and decrypting saved passwords from database...")
        
        # get and decrypt passwords
        passwords = get_passwords_from_db(selected_browser, secret)
        
        # display results
        if isinstance(passwords, str):  # error message
            print(passwords)
        else:
            print(f"\nFound {len(passwords)} saved passwords:")
            print("=" * 60)
            for url, username, password in passwords:
                print(f"URL: {url}")
                print(f"Username: {username}")
                print(f"Password: {password}")
                print("-" * 60)
        
    except (ValueError, IndexError):
        print("Invalid choice.")
