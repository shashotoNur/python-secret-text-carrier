# Python Hide

A command line python program to hide and read text data in jpg files.

## Installation

Make sure to have `cryptography` installed,

```
pip install cryptography
```


### Sample

There is already a jpg file with an encrypted data.

To read it, open up your terminal and run the main python file.

`python main.py`

Input the password: `test1234`

Input the filepath: `target.jpg` (You don't need to write the complete path because it's in the same directory.)

Input your choice to read: `2`

Upon entering all of the inputs correctly, the program will show you the message hidden in the file.

## How it works

While hiding, the program takes a message and encrypts it against a password.

The file specified by the user is appended by the encrypted string.

While reading, the program takes the password and the path to the carrier file. It reads the file and gets to the end of the file data (specified by hex, FFD9) and extracts the data after it. This is the encrypted string. It is then decrypted against the password.

All the cryptographic operations are handled by the `cryptography` library.
