import nltk
import enchant

nltk.download('words')

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def caesar_decrypt(message, key):
    translated = ''
    for symbol in message:
        if symbol in LETTERS:
            if symbol.islower():
                letters_count = len(LETTERS) // 2
                num = (LETTERS.find(symbol) - key + letters_count) % letters_count
                translated += LETTERS[num + letters_count]
            else:
                num = (LETTERS.find(symbol) - key) % len(LETTERS)
                translated += LETTERS[num]
        else:
            translated += symbol
    return translated

def is_english_word(word):
    dictionary = enchant.Dict("en_US")
    return dictionary.check(word.lower())

def is_valid_message(message, word_list):
    words = message.split()
    valid_words = [word for word in words if word.lower() in word_list]
    return len(valid_words) >= len(words) // 2

def brute_force_decrypt(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
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
