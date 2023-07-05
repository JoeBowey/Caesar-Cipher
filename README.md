# Caesar-Cipher
A Caesar Cipher code including a brute force code to decrypt the encrypted message

accode.py 
- An advanced caesar cipher code which uses fernet to generate a random key with the user input. The plaintext data is then encrypted and stored in the encrypteddata folder. 
- When decrypting the user recieves a list of all the encrypted data, the user can then choose which ciphertext they want to decrypt and in any order.
- When the code is closed and reloaded, all the previous encrypted data is still stored with its assigned key, so it works after closing the code.
- THe user has the option to delete all the keys and text data,

caesar_cipher_gui.py
- Uses the same code from accode.py but uses tkinter to have a usuable gui to make it look better.

bfcc.py
- A brute force code which reads the encrypted data and runs through every shift of key and when it reads the data which looks and sounds like an actual message, it will decided that is the original encrypted message.accode.py 
- An advanced caesar cipher code which uses fernet to generate a random key with the user input. The plaintext data is then encrypted and stored in the encrypteddata folder. 



