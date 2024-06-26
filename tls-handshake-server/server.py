import sys
import string
import random
import subprocess
import time
import json
from queue import Queue
from base64 import b64encode, b64decode
import threading  # Import threading module
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad  # Import pad and unpad

# Initialize variables to hold parsed values
p = ""
g = ""
root_key_d = ""
root_certificate = ""
root_certificate_signature = ""
name = ""
A = ""
user_key = None
root_key_e = 0
root_key_n = 0
shared_secret_key = None  # To store the derived AES key
cipher_encrypt = None  # Global cipher object



def parse_output_line(line):
    """ Parse the line and assign values to variables """
    global p, g, root_key_d, root_certificate, root_certificate_signature, name, A

    if line.startswith("p:"):
        p = line.split(":", 1)[1].strip()
    elif line.startswith("g:"):
        g = line.split(":", 1)[1].strip()
    elif line.startswith("root key d:"):
        root_key_d = line.split(":", 1)[1].strip()
    elif line.startswith("root certificate (b64):"):
        root_certificate = line.split(":", 1)[1].strip()
    elif line.startswith("root certificate signature (b64):"):
        root_certificate_signature = line.split(":", 1)[1].strip()
    elif line.startswith("name:"):
        name = line.split(":", 1)[1].strip()
    elif line.startswith("A:"):
        A = line.split(":", 1)[1].strip()

def read_output(process, stream_name, input_queue):
    """ Continuously read and print process output and detect patterns. """
    stream = getattr(process, stream_name)
    secret_ciphertext = None
    buffer = ""

    try:
        while True:
            output = stream.read(1)
            if output == '':
                break
            sys.stdout.write(output)
            sys.stdout.flush()
            buffer += output
            if output == '\n':  # End of line
                parse_output_line(buffer)
                buffer = ""

            if "B:" in buffer:
                B = calculate_B()
                input_queue.put(str(hex(B)) + '\n')  # Convert B to hex and add newline
                buffer = ""
            elif "user certificate (b64):" in buffer:
                user_certificate_b64, user_certificate_signature_b64 = generate_user_certificate_and_signature()
                encrypted_certificate_b64 = encrypt_user_certificate(user_certificate_b64)
                input_queue.put(encrypted_certificate_b64 + '\n')  # Send the encrypted certificate and add newline
                buffer = ""
            elif "user certificate signature (b64):" in buffer:
                encrypted_signature_b64 = encrypt_user_certificate(user_certificate_signature_b64)
                input_queue.put(encrypted_signature_b64 + '\n')  # Send the encrypted certificate signature and add newline
                buffer = ""
            elif "user signature (b64):" in buffer:
                user_signature_b64 = generate_user_signature()
                encrypted_signature_b64 = encrypt_user_certificate(user_signature_b64)
                input_queue.put(encrypted_signature_b64 + '\n')  # Send the encrypted user signature and add newline
                buffer = ""

            elif "secret ciphertext (b64):" in buffer:
                # Extract everything after the tag
                secret_ciphertext = buffer.split("secret ciphertext (b64):", 1)[1].strip()
        print("00000000: ", secret_ciphertext)
        ciphertext = b64decode(secret_ciphertext)
        plaintext = cipher_decrypt.decrypt(ciphertext)
        plaintext = unpad(plaintext, AES.block_size)
        print("Decrypted text:", plaintext.decode('utf-8'))
    except Exception as e:
        print(f"Error reading {stream_name}: {e}", file=sys.stderr)

def write_input(process, input_queue):
    """ Write inputs from the queue to the process. """
    try:
        while True:
            input_data = input_queue.get()
            if input_data is None:  # Exit signal
                break
            process.stdin.write(input_data)
            process.stdin.flush()
            sys.stdout.write(input_data)  # Print the input we send
            sys.stdout.flush()
            time.sleep(1)  # Add a short delay to give time for the process to output
    except BrokenPipeError:
        print("Subprocess ended. Exiting...")

def calculate_B():
    """ Calculate B using parsed values and a hardcoded b """
    global p, g, shared_secret_key, B, cipher_encrypt, cipher_decrypt
    p = int(p, 16)
    g = int(g, 16)
    A_int = int(A, 16)
    b = 0xdeadbeef
    B = pow(g, b, p)
    s = pow(A_int, b, p)
    shared_secret_key = SHA256.new(s.to_bytes(256, 'little')).digest()[:16]
    cipher_encrypt = AES.new(key=shared_secret_key, mode=AES.MODE_CBC, iv=b'\0' * 16)  # Initialize the cipher here
    cipher_decrypt = AES.new(key=shared_secret_key, mode=AES.MODE_CBC, iv=b'\0' * 16)


    return B

def generate_user_certificate_and_signature():
    """ Generate the user certificate and its signature, encode both in base64 """
    global root_certificate, root_certificate_signature, root_key_d, root_key_n, user_key, name

    # Decode the provided root certificate and signature
    root_certificate_data = b64decode(root_certificate)
    root_certificate_signature = b64decode(root_certificate_signature)

    # Extract root certificate information
    root_certificate_json = json.loads(root_certificate_data)
    root_key_e = int(root_certificate_json["key"]["e"])
    root_key_n = int(root_certificate_json["key"]["n"])

    # Ensure root_key_d is an integer
    root_key_d = int(root_key_d, 16)

    # Create the user certificate
    while True:
        user_key = RSA.generate(1024)
        n = user_key.n
        if 2**512 < n < 2**1024:
            break

    user_certificate = {
        "name": name,
        "key": {
            "e": user_key.e,
            "n": user_key.n,
        },
        "signer": "root",
    }

    # Convert user certificate to JSON and encode to bytes
    user_certificate_data = json.dumps(user_certificate).encode()
    user_certificate_data_b64 = b64encode(user_certificate_data).decode()

    # Sign the user certificate data with the root private key
    user_certificate_hash = SHA256.new(user_certificate_data).digest()
    user_certificate_signature = pow(
        int.from_bytes(user_certificate_hash, "little"),
        root_key_d,
        root_key_n
    ).to_bytes(256, "little")
    user_certificate_signature_b64 = b64encode(user_certificate_signature).decode()

    return user_certificate_data_b64, user_certificate_signature_b64

def generate_user_signature():
    """ Generate the user signature, encode it in base64 """
    global name, A, B, user_key

    # Create the user signature data
    user_signature_data = (
        name.encode().ljust(256, b"\0") +
        int(A, 16).to_bytes(256, "little") +
        int(hex(B), 16).to_bytes(256, "little")
    )

    # Compute the SHA-256 hash of the user signature data
    user_signature_hash = SHA256.new(user_signature_data).digest()

    # Encrypt the hash with the user's private key
    user_signature = pow(
        int.from_bytes(user_signature_hash, "little"),
        user_key.d,
        user_key.n
    ).to_bytes(256, "little")
    user_signature_b64 = b64encode(user_signature).decode()

    return user_signature_b64

def encrypt_user_certificate(data_b64):
    """ Encrypt the user certificate data """
    global cipher_encrypt
    # Encrypt the data
    data = b64decode(data_b64)
    encrypted_data = cipher_encrypt.encrypt(pad(data, 16))
    encrypted_data_b64 = b64encode(encrypted_data).decode()
    return encrypted_data_b64


def main():
    input_queue = Queue()

    # Start the challenge subprocess
    process = subprocess.Popen(
        ['/challenge/run'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # Line-buffered mode
    )

    # Start threads to read and print the subprocess output and errors continuously
    output_thread = threading.Thread(target=read_output, args=(process, 'stdout', input_queue))
    output_thread.daemon = True
    output_thread.start()

    error_thread = threading.Thread(target=read_output, args=(process, 'stderr', input_queue))
    error_thread.daemon = True
    error_thread.start()

    input_thread = threading.Thread(target=write_input, args=(process, input_queue))
    input_thread.daemon = True
    input_thread.start()

    try:
        output_thread.join()
        error_thread.join()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Ensure the subprocess is terminated
        process.terminate()
        process.wait()
        input_queue.put(None)  # Signal the input thread to exit
        input_thread.join()

if __name__ == "__main__":
    main()
