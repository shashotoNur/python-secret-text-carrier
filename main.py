
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _derive_key(password: bytes, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=default_backend()
    )

    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = 100_000) -> bytes:
    """Encrypt a message against a key generated from a password"""
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)

    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    """Decrypt a encrypted byte string from a password"""
    try:
        decoded = b64d(token)
        salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
        iterations = int.from_bytes(iter, 'big')
        key = _derive_key(password.encode(), salt, iterations)

        return Fernet(key).decrypt(token)
    except:
        print("Decryption failed!")


def main() :
    print('\033[1m' + "\nHIDE Information In JPG Files\n" + '\033[0m')
    password = input("Password: ")
    file_path = input("JPG file path: ")

    try:
        choice = int(input("Choices:\n\t1. Hide\n\t2. Read\n\t3. Reset\nEnter your choice: "))
        if(choice == 1):
            message = input("Message: ")
            encrypted_msg = password_encrypt(message.encode(), password)
            try:
                """Write encrypted data to a file"""
                with open(file_path, 'ab') as f:
                    f.write(encrypted_msg)
            except:
                """Invalid file path input"""
                print("File not found!")

        elif(choice == 2):
            try:
                """Read encrypted byte data from the carrier file"""
                with open(file_path, 'rb') as f:
                    content = f.read()
                    """JPG files end with Hex code FFD9"""
                    offset = content.index(bytes.fromhex('FFD9')) + 2

                    f.seek(offset)
                    encrypted_bytes = f.read()
                    decrypted_msg = password_decrypt(encrypted_bytes, password)

                    if(decrypted_msg != None):
                        print("Message: \x1b[6;30;42m" + decrypted_msg.decode() + "\x1b[0m")
            except:
                print("File not found!")
        
        elif(choice == 3):
            f = open(file_path, "rb")
            content = f.read()
            offset = content.index(bytes.fromhex('FFD9')) + 2
            f.close()

            f = open(file_path, "a")
            f.truncate(offset)
            f.close()

        else:
            print("Choose between 1, 2 or 3")

    except:
        print("Not an integer!")

    print("\n\nProgram terminated...")


main()