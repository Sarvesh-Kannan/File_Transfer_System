import socket
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import pickle
import os

def merkle_tree(file_chunks):
    tree = [hashlib.sha256(chunk).hexdigest() for chunk in file_chunks]
    while len(tree) > 1:
        if len(tree) % 2 != 0:
            tree.append(tree[-1])
        tree = [hashlib.sha256(tree[i].encode('utf-8') + tree[i + 1].encode('utf-8')).hexdigest() for i in range(0, len(tree), 2)]
    return tree[0]

def encrypt_file(file_path, key):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = b""  # Initialize an empty byte string

    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(256)
            if not chunk:
                break
            # Pad the chunk to be a multiple of the block size
            padded_chunk = chunk.ljust(256, b'\0')  
            encrypted_chunk = encryptor.update(padded_chunk)
            encrypted_data += encrypted_chunk
    return iv + encrypted_data

def decrypt_file(encrypted_data, key):
    try:
        iv = encrypted_data[:16]  # Extract the IV from the beginning
        encrypted_data = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return decrypted_data
    except:
        pass

def main():
    host = '172.20.10.2'
    port = 12010

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    key = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    print(f"Generated Key: {key.hex()}")

    # Get user input for the operation (upload or download)
    operation = input("Enter 'upload' or 'download' for the desired operation: ")

    if operation.lower() == "upload":
        # Send the chosen operation to the server
        client_socket.sendall(operation.encode())

        # Get user input for the file path
        file_path = input("Enter the file path to transfer: ")
        fname = file_path.split('\\')[-1]

        # Send file path to the server
        client_socket.sendall(fname.encode())

        # Encrypt and send file as binary data
        encrypted_data = encrypt_file(file_path, key)
        blocks = [encrypted_data[i:i + 256] for i in range(0, len(encrypted_data), 256)]
        merkle_tree_hash = merkle_tree(blocks)

        with open(fname + '.bin', 'wb') as f:
            pickle.dump(merkle_tree_hash, f)

        print(f"Generated Merkerl Hash:{merkle_tree_hash}")
        client_socket.sendall(encrypted_data)

    elif operation.lower() == "download":
        # Send the chosen operation to the server
        client_socket.sendall(operation.encode())

        # Get user input for the file name to download
        file_name_to_download = input("Enter the file name to download: ")

        # Send the file name to the server
        client_socket.sendall(file_name_to_download.encode())

        # Receive the encrypted file data from the server
        encrypted_data = client_socket.recv(1000000)

        blocks = [encrypted_data[i:i + 256] for i in range(0, len(encrypted_data), 256)]
        merkle_tree_hash = merkle_tree(blocks)

        print(merkle_tree_hash)

        with open(file_name_to_download + '.bin', 'rb') as f:
            old_hash = pickle.load(f)

        if old_hash == merkle_tree_hash:
            print("File integrity is maintained")
        else:
            print("file integrity is compromised") 

        # Decrypt and save the file locally
        decrypted_data = decrypt_file(encrypted_data, key)
        try:
            if decrypted_data is not None:
                trimmed_binary_string = decrypted_data.rstrip(b'\x00')
            else:
                print('Decryption failed: Encrypted data was modified')
        except Exception as e:
            pass

        with open(file_name_to_download, 'wb') as file:
            try:
                file.write(trimmed_binary_string)
                print(f"Downloaded file '{file_name_to_download}' saved locally.")
            except:
                pass

    else:
        print("Invalid operation. Please enter 'upload' or 'download'.")

if __name__ == "__main__":
    main()

