import socket
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_merkle_tree(file_chunks):
    tree = [hashlib.sha256(chunk).hexdigest() for chunk in file_chunks] 
    while len(tree) > 1:
        tree = [hashlib.sha256((tree[i] + tree[i + 1]).encode()).hexdigest() for i in range(0, len(tree), 2)]
    return tree[0]

def decrypt_file(encrypted_data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def receive_file_and_verify():
    host = '172.20.10.2'
    port = 12010

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    
    while True:
        server_socket.listen()
        print(f"Server listening on {host}:{port}")
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            option = conn.recv(10000000)
            if option.lower() == b'upload':
                file_path = conn.recv(10000000).decode()
                print(f"Received File Path: {file_path}")

                encrypted_data = conn.recv(10000000)
                print("Received Encrypted File")

                with open(file_path, 'wb') as file:
                    file.write(encrypted_data)

                blocks = [encrypted_data[i:i + 256] for i in range(0, len(encrypted_data), 256)]
                merkle_tree_hash = generate_merkle_tree(blocks)
                print(merkle_tree_hash)

            else:
                file_path = conn.recv(10000000).decode()
                print(f"Received File Path: {file_path}")
      
                with open(file_path, 'rb') as f:
                    data = f.read()   
                conn.send(data) 
            conn.close()

if __name__ == "__main__":
    receive_file_and_verify()
