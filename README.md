# Password Fortress (Password Generation and Encryption Program)

This Python program is designed to generate, encrypt, and securely store passwords. It allows users to create strong, customizable passwords, with options for length and the inclusion of special characters. The generated passwords are encrypted using AES encryption and safely stored in a JSON file, accessible only with a main password.

## Features

- **Random Password Creation**: Generate passwords with a specified length.
- **Customizable Special Character Inclusion**: Choose to include a specific number of special characters in the password.
- **AES Encryption**: Encrypts passwords using Advanced Encryption Standard (AES) before saving.
- **Secure Storage**: Stores encrypted passwords in a JSON file (`password_store.json`), along with the associated website name.
- **Password Retrieval**: Access and decrypt stored passwords by providing the correct main password and the corresponding website name.

## Requirements

- Python 3.x
- `cryptography` package (for AES encryption)

You can install the `cryptography` package via pip:

```bash
pip install cryptography
