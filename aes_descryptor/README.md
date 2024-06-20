
### Overview
AESByteDecryptor is designed to decrypt messages encrypted using AES encryption in ECB mode with 16-byte block sizes. It works by leveraging a side-channel vulnerability where encrypted outputs can be manipulated and compared against known values to deduce the plaintext.

### How It Works
The program interacts with an external process that expects a Base64-encoded input, encrypts it using AES-ECB, and then outputs both the ciphertext in hexadecimal format and the input in Base64. By systematically adjusting the input and analyzing the changes in the encrypted output, AESByteDecryptor can infer the original plaintext byte by byte.
