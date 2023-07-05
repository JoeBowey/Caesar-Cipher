"""
Joe Bowey
Brute Force for Caesar Cipher code
"""

import nltk
import enchant

# Download the 'words' corpus from NLTK
nltk.download('words')

# Define the letters used for encryption and decryption
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def caesar_decrypt(message, key):
    """
    Decrypts a message encrypted using the Caesar cipher with a given key.
    
    Args:
        message (str): The encrypted message.
        key (int): The decryption key.
    
    Returns:
        str: The decrypted message.
    """
    translated = ''
    for symbol in message:
        if symbol in LETTERS:
            if symbol.islower():
                # Decrypt lowercase letter
                letters_count = len(LETTERS) // 2
                num = (LETTERS.find(symbol) - key + letters_count) % letters_count
                translated += LETTERS[num + letters_count]
            else:
                # Decrypt uppercase letter
                num = (LETTERS.find(symbol) - key) % len(LETTERS)
                translated += LETTERS[num]
        else:
            # Keep non-alphabetic characters as they are
            translated += symbol
    return translated

def is_english_word(word):
    """
    Checks if a word is an English word using a dictionary lookup.
    
    Args:
        word (str): The word to check.
    
    Returns:
        bool: True if the word is an English word, False otherwise.
    """
    dictionary = enchant.Dict("en_US")
    return dictionary.check(word.lower())

def is_valid_message(message, word_list):
    """
    Checks if a message contains a sufficient number of English words.
    
    Args:
        message (str): The message to check.
        word_list (list): List of English words.
    
    Returns:
        bool: True if the message is valid, False otherwise.
    """
    words = message.split()
    valid_words = [word for word in words if word.lower() in word_list]
    return len(valid_words) >= len(words) // 2

def brute_force_decrypt(file_path):
    """
    Performs brute-force decryption of messages in a file using the Caesar cipher.
    
    Args:
        file_path (str): The path to the file containing encrypted messages.
    """
    # Load the list of English words
    with open('english_words.txt', 'r') as file:
        word_list = [word.strip() for word in file]

    # Read and decrypt each line in the file
    with open(file_path, 'r') as file:
        lines = file.readlines()
        if len(lines) == 0:
            print("No Encrypted Data Available.")
            return  # Exit the function if there is no encrypted data

        for line in lines:
            line = line.strip()
            print("Encrypted message:", line)
            print("Decrypting...\n")
            for key in range(26):
                decrypted_text = caesar_decrypt(line, key)
                print("Hacking key #{}: {}".format(key, decrypted_text))
                words = decrypted_text.split()
                if all(is_english_word(word) for word in words):
                    print("\nValid decrypted message found:")
                    print(decrypted_text)
                    break
            else:
                print("No valid decrypted messages found.")
            print("\n")

# Usage example
file_path = '/home/kali/Documents/Projects/Caesar Ciper/Caesarcipherad/encrypteddata/encryptedtext.txt'
brute_force_decrypt(file_path)
