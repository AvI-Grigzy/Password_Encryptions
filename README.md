# Password Fortress (Password Generation and Encryption Program)

This repository contains two versions of the program: one written in Java (.java) and another in Python (.py). You can run the program in either language, depending on your preference or setup.

This program is designed to generate, encrypt, and securely store passwords. It allows users to create strong, customizable passwords, with options for length and the inclusion of special characters. The generated passwords are encrypted using AES encryption and safely stored in a JSON file, accessible only with a main password.

## Features

- **Random Password Creation**: Generate passwords with a specified length.
- **Customizable Special Character Inclusion**: Choose to include a specific number of special characters in the password.
- **AES Encryption**: Encrypts passwords using Advanced Encryption Standard (AES) before saving.
- **Secure Storage**: Stores encrypted passwords in a JSON file (`password_store.json`), along with the associated website name.
- **Password Retrieval**: Access and decrypt stored passwords by providing the correct main password and the corresponding website name.

## Requirements

### For Java:
- **Java 8** or higher must be installed on your system to run the `.java` file.

### For Python:
- **Python 3.x** must be installed to run the `.py` file.
- **Cryptography package** is required for AES encryption. You can install it using pip with the following command:

```bash
pip install cryptography
