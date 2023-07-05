"""
Joe Bowey
Advanced Caesar Cipher with usuable GUI
"""

import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import os

encrypted_texts = []  # List to store encrypted texts and their associated keys
encrypted_data = []  # List to store tuples of (key, encrypted_text)
key_storage = []  # List to store generated keys

# Create folders if they don't exist
if not os.path.exists("key"):
    os.makedirs("key")
if not os.path.exists("encrypteddata"):
    os.makedirs("encrypteddata")
if not os.path.exists("decrypteddata"):
    os.makedirs("decrypteddata")

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

def on_encrypt():
    key = Fernet.generate_key()
    key = int.from_bytes(key, 'big') % 26
    key_storage.append(key)

    text = entry.get()
    ciphertext = encrypt_decrypt(text, 'e', key)

    with open('encrypteddata/encryptedtext.txt', 'a') as file:
        file.write(f'{ciphertext}\n')

    encrypted_data.append((ciphertext, str(key)))

    messagebox.showinfo("Encryption Complete", f"CIPHERTEXT: {ciphertext}")

    # Update the listbox with the new encrypted text
    listbox.insert(tk.END, f'{len(encrypted_data)}. {ciphertext}')

def on_decrypt():
    if len(encrypted_data) == 0:
        messagebox.showinfo("No Encrypted Texts", "No encrypted texts available. Encrypt some texts first.")
        return

    selected_index = listbox.curselection()
    if not selected_index:
        messagebox.showinfo("No Selection", "Please select an encrypted text to decrypt.")
        return

    selection = selected_index[0]
    selected_text, key = encrypted_data[selection]
    key = int(key)
    plaintext = encrypt_decrypt(selected_text, 'd', key)

    decrypted_filename = f'decrypteddata/decrypted_{selection + 1}.txt'
    with open(decrypted_filename, 'w') as file:
        file.write(plaintext)

    messagebox.showinfo("Decryption Complete", f"PLAINTEXT: {plaintext}\nDecrypted text saved to: {decrypted_filename}")

def on_delete_all():
    delete_files("encrypteddata")
    delete_files("decrypteddata")
    delete_files("key")
    encrypted_data.clear()
    key_storage.clear()
    messagebox.showinfo("Delete Complete", "All encrypted texts, decrypted texts, and keys have been deleted.")

def on_exit():
    # Save key storage to file
    with open("key/key_storage.txt", 'w') as file:
        file.write('\n'.join(map(str, key_storage)))

    # Save encrypted data to file
    with open("encrypteddata/encrypted_data.txt", 'w') as file:
        file.write('\n'.join([f'{text}:{key}' for text, key in encrypted_data]))

    root.destroy()

root = tk.Tk()
root.title("Caesar Cipher Program")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

label = tk.Label(frame, text="Enter the text to encrypt:")
label.pack()

entry = tk.Entry(frame, width=40)
entry.pack(pady=5)

encrypt_button = tk.Button(frame, text="Encrypt", command=on_encrypt)
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = tk.Button(frame, text="Decrypt", command=on_decrypt)
decrypt_button.pack(side=tk.LEFT, padx=5)

delete_button = tk.Button(frame, text="Delete All", command=on_delete_all)
delete_button.pack(side=tk.LEFT, padx=5)

exit_button = tk.Button(frame, text="Exit", command=on_exit)
exit_button.pack(side=tk.LEFT, padx=5)

listbox_frame = tk.Frame(root)
listbox_frame.pack(padx=10, pady=5)

listbox_label = tk.Label(listbox_frame, text="Encrypted texts:")
listbox_label.pack()

listbox = tk.Listbox(listbox_frame, selectmode=tk.SINGLE, width=50, height=5)
listbox.pack(side=tk.LEFT, fill=tk.BOTH)

scrollbar = tk.Scrollbar(listbox_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

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

# Populate the listbox with encrypted texts
for i, (text, _) in enumerate(encrypted_data):
    listbox.insert(tk.END, f'{i+1}. {text}')

root.mainloop()
