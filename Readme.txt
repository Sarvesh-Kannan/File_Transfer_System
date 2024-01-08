DSA-PROJECT

Secure File Transfer with AES Encryption and Merkle Tree Verification
This project demonstrates a secure file transfer system between a client and server using Python. The communication is secured with Advanced Encryption Standard (AES) encryption in Cipher Block Chaining (CBC) mode, and the file integrity is verified using a Merkle tree.

Features

AES Encryption: Data transmission between the client and server is encrypted using AES encryption for confidentiality.

Merkle Tree Verification: The integrity of transferred files is ensured through the use of Merkle trees. This cryptographic hash tree allows for efficient verification of file integrity.

Socket Programming: The client and server communicate over a TCP/IP connection using Python's socket module.

Setup
Install Dependencies:

pip install cryptography
Run Server:

Open a terminal and navigate to the server directory.
Run the server script:
python server.py
Run Client:

Open a separate terminal and navigate to the client directory.
Run the client script:
 python client.py
Usage
Client:

Upon running the client script, it will prompt you to choose an operation: "upload" or "download."
Upload Operation:

Choose "upload" to send a file to the server.
Enter the file path when prompted.
The file is encrypted with AES, and a Merkle tree hash is calculated and sent to the server along with the encrypted data.
Download Operation:

Choose "download" to retrieve a file from the server.
Enter the file name when prompted.
The server sends the encrypted file and Merkle tree hash. The client verifies the integrity using the received hash before decrypting and saving the file.
File Integrity Check:

During both upload and download operations, the Merkle tree hash is used to verify the integrity of the transferred file. If the local and received hashes match, the file is considered intact.
Important Notes
Key Management:

The project uses a hardcoded key for simplicity. In real-world scenarios, implement secure key exchange mechanisms.
Exception Handling:

The code includes basic exception handling for improved robustness. Modify it as needed for specific use cases.
Security Considerations:

This project provides a basic understanding of secure file transfer. For production systems, consider additional security measures, such as secure key management and HTTPS for secure transport layer.
@Sarvesh-Kannan's File transfer system
View 1
Filter by keyword or by field
You
