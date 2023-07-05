"""
Joe Bowey
Caesar Cipher
"""

import os
from cryptography.fernet import Fernet

encrypted_texts = []  # List to store encrypted texts and their associated keys
encrypted_data = []  # List to store tuples of (key, encrypted_text)
key_storage = []  # List to store generated keys


def encrypt_decrypt(text, mode, key):
    """
    Encrypts or decrypts the given text using the Caesar cipher algorithm.

    Args:
        text (str): The text to be encrypted or decrypted.
        mode (str): 'e' for encryption, 'd' for decryption.
        key (int): The encryption or decryption key.

    Returns:
        str: The encrypted or decrypted text.
    """
    result = ""
    if mode == 'd':
        key = (26 - key) % 26  # Calculate the inverse key for decryption
    for char in text:
        if char.isalpha():
            if char.isupper():
                index = ord(char) - ord('A')
                new_index = (index + key) % 26  # Encryption or decryption
                result += chr(new_index + ord('A'))
            else:
                index = ord(char) - ord('a')
                new_index = (index + key) % 26  # Encryption or decryption
                result += chr(new_index + ord('a'))
        else:
            result += char
    return result


# Create folders if they don't exist
if not os.path.exists("key"):
    os.makedirs("key")
if not os.path.exists("encrypteddata"):
    os.makedirs("encrypteddata")
if not os.path.exists("decrypteddata"):
    os.makedirs("decrypteddata")

# Load key storage and encrypted data from file if they exist
key_storage_filename = "key/key_storage.txt"
if os.path.exists(key_storage_filename):
    with open(key_storage_filename, 'r') as file:
        stored_keys = file.read().splitlines()
        key_storage = [int(key) for key in stored_keys]

encrypted_data_filename = "encrypteddata/encrypted_data.txt"
if os.path.exists(encrypted_data_filename):
    with open(encrypted_data_filename, 'r') as file:
        stored_encrypted_data = file.read().splitlines()
        encrypted_data = [tuple(item.split(':')) for item in stored_encrypted_data]


def delete_files(folder):
    """
    Deletes all files in the specified folder.

    Args:
        folder (str): The path to the folder containing the files.
    """
    files = os.listdir(folder)
    for file_name in files:
        file_path = os.path.join(folder, file_name)
        os.remove(file_path)


while True:
    # Print menu and get user input
    print()
    print('*** CAESAR CIPHER PROGRAM ***')
    print('*** 1. Encrypt            ***')
    print('*** 2. Decrypt            ***')
    print('*** 3. Delete All         ***')
    print('*** 4. Exit               ***')
    print('*** CAESAR CIPHER PROGRAM ***')
    print()

    user_input = input('Enter your choice (1-4): ')
    print()

    if user_input == '1':
        # Encryption mode
        print('ENCRYPTION MODE')
        print()
        key = Fernet.generate_key()
        key = int.from_bytes(key, 'big') % 26
        key_storage.append(key)
        key_filename = f'key/key_{len(key_storage)}.txt'  # Generate a unique key filename
        with open(key_filename, 'w') as file:
            file.write(str(key))
        print('Random key generated:', key)

        text = input('Enter the text to encrypt: ')
        ciphertext = encrypt_decrypt(text, user_input, key)

        with open('encrypteddata/encryptedtext.txt', 'a') as file:
            file.write(f'{ciphertext}\n')

        # Store the key and encrypted text in the encrypted data list
        encrypted_data.append((ciphertext, str(key)))

        print(f'CIPHERTEXT: {ciphertext}')

    elif user_input == '2':
        # Decryption mode
        if len(encrypted_data) == 0:
            print('No encrypted texts available. Encrypt some texts first.')
        else:
            print('DECRYPTION MODE')
            print()
            print('Encrypted texts:')
            for i, (text, _) in enumerate(encrypted_data):
                print(f'{i+1}. {text}')
            selection = int(input('Enter the number of the text to decrypt: '))
            if 1 <= selection <= len(encrypted_data):
                selected_text, key = encrypted_data[selection - 1]
                key = int(key)  # Convert the key back to an integer
                plaintext = encrypt_decrypt(selected_text, 'd', key)
                print(f'PLAINTEXT: {plaintext}')
                
                decrypted_filename = f'decrypteddata/decrypted_{selection}.txt'  # Generate a unique decrypted filename
                with open(decrypted_filename, 'w') as file:
                    file.write(plaintext)
                print(f'Decrypted text saved to: {decrypted_filename}')
            else:
                print('Invalid selection.')


    elif user_input == '3':
        # Delete all encrypted texts, decrypted texts, and keys
        delete_files("encrypteddata")
        delete_files("decrypteddata")
        delete_files("key")
        encrypted_data = []
        key_storage = []
        print("All encrypted texts, decrypted texts, and keys have been deleted.")

    elif user_input == '4':
        # Exit the program
        print("Exiting the program...")

        # Save key storage to file
        with open(key_storage_filename, 'w') as file:
            file.write('\n'.join(map(str, key_storage)))

        # Save encrypted data to file
        with open(encrypted_data_filename, 'w') as file:
            file.write('\n'.join([f'{text}:{key}' for text, key in encrypted_data]))

        break

    else:
        print("Invalid choice. Please select again.")
