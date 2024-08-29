import os
import base64
import json
import getpass
import random
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Let's create a fortress for your passwords! (Generate a random password)
def generate_password(length, special_char_count):
    characters = string.ascii_letters + string.digits
    special_characters = string.punctuation

    if special_char_count > length:
        raise ValueError("Number of special characters cannot exceed total password length")

    # Build a strong password foundation with letters and digits
    password = ''.join(random.choice(characters) for i in range(length - special_char_count))
    password += ''.join(random.choice(special_characters) for i in range(special_char_count))

    # Shuffle it up! We don't want any patterns here
    password = ''.join(random.sample(password, len(password)))

    return password

# Turn your master password into an unbreakable key
def derive_key(main_password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,  # 32 bytes = 256-bit key, solid as a rock!
        n=2**14,    # CPU/memory cost factor, higher = more secure (and slower)
        r=8,        # Block size (related to parallelism)
        p=1,        # Parallelization factor
        backend=default_backend()
    )
    key = kdf.derive(main_password.encode())  # Transform your password into a key
    return key

# Lock that password in a vault! (Encrypt the password)
def encrypt_password(password, key):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted_password).decode('utf-8')

# Open the vault and retrieve your password (Decrypt the password)
def decrypt_password(encrypted_password, key):
    data = base64.urlsafe_b64decode(encrypted_password.encode('utf-8'))
    iv = data[:16]  # Extract the IV used during encryption
    encrypted_password = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_password) + decryptor.finalize()

# Store your treasure securely in a file (Store the password)
def store_password(file_path, website, encrypted_password, salt):
    data = {
        "salt": base64.urlsafe_b64encode(salt).decode('utf-8'),
        "website": website,
        "encrypted_password": encrypted_password
    }
    with open(file_path, 'a') as file:  # Append the new entry to the file
        file.write(json.dumps(data) + "\n")  # Save each entry as a new line

# Retrieve your treasure with the correct key (Load and decrypt the password)
def load_password(file_path, main_password, website):
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()  # Trim any extra spaces or newlines
            if line:  # Make sure we're not processing an empty line
                try:
                    data = json.loads(line)  # Decode the JSON data
                    if data.get('website') == website:  # Match the website
                        salt = base64.urlsafe_b64decode(data['salt'].encode('utf-8'))
                        encrypted_password = data['encrypted_password']
                        key = derive_key(main_password, salt)
                        
                        try:
                            password = decrypt_password(encrypted_password, key)
                            return password.decode('utf-8')
                        except Exception as e:
                            print("Failed to decrypt password. The main password may be incorrect.")
                            return None
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON on line: {line}")
                    print(f"Error details: {e}")
    print("No password found for the specified website.")
    return None

# Welcome to your password fortress! (Main function)
def main():
    choice = input("Do you want to (G)enerate a new password or (A)ccess stored password? [G/A]: ").upper()
    
    if choice == 'G':
        website = input("Enter the website name: ")
        length = int(input("Enter the desired length of the password: "))
        special_char_option = input("Do you want to include special characters? (Y/N): ").upper()
        special_char_count = 0

        if special_char_option == 'Y':
            special_char_count = int(input("How many special characters do you want to include?: "))

        password = generate_password(length, special_char_count)
        print(f"Generated password for {website}: {password}")
        
        main_password = getpass.getpass("Enter a main password to secure your passwords: ")
        salt = os.urandom(16)
        key = derive_key(main_password, salt)
        encrypted_password = encrypt_password(password, key)
        
        file_path = "password_store.json"
        store_password(file_path, website, encrypted_password, salt)
        print(f"Password stored securely in {file_path}.")
    
    elif choice == 'A':
        website = input("Enter the website name to retrieve the password: ")
        file_path = "password_store.json"
        main_password = getpass.getpass("Enter your main password to access stored passwords: ")
        password = load_password(file_path, main_password, website)
        
        if password:
            print(f"Your stored password for {website} is: {password}")
        else:
            print("Could not retrieve the password.")
    else:
        print("Invalid option. Please choose either G or A.")

if __name__ == "__main__":
    main()
