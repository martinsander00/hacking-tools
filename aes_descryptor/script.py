import subprocess
import base64
import time

def create_challenge_process():
    command = ['/challenge/run']
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    return process

def run_initial_command(process):
    # Read initial output to clear any default messages
    output = []
    while True:
        line = process.stdout.readline()
        output.append(line)
        if 'ciphertext (hex): ' in line:  # Assume the initial output always contains this line
            break  # Stop after reading the first set of ciphertext (you might adjust this based on actual needs)


def run_command_with_input(process, input_data):
    process.stdin.write(input_data.decode('utf-8') + '\n')
    process.stdin.flush()
    output = []
    while True:
        line = process.stdout.readline()
        output.append(line)
        if 'ciphertext (hex): ' in line:
            break
    return ''.join(output)

def extract_ciphertext(output):
    hex_start = output.find('ciphertext (hex): ') + 18
    hex_end = output.find('\n', hex_start)
    ciphertext_hex = output[hex_start:hex_end].replace(' ', '')
    return ciphertext_hex


def decrypt_byte_at_a_time(process):
    block_size = 16  # Known block size from AES
    discovered_secret = ""
    match_count = []
    initial_num_as = 7  # Initial number of 'a's

    counter = 0

    # Outer loop: Increase the number of 'a's starting from 6
    for num_as in range(initial_num_as, 55):
        print("")
        print("---------------------------------------------------------------")
        print("")
        print("Outerloop counter: ", num_as)
        prefix = b"a" * num_as
        print("Us before running the first command with this input: ", base64.b64encode(prefix))

        baseline_output = run_command_with_input(process, base64.b64encode(prefix))
        print("This is baseline_output: ", baseline_output)

        baseline_ciphertext = extract_ciphertext(baseline_output)
        print("OUTER LOOP extracted ciphertext: ", baseline_ciphertext)

        if num_as < initial_num_as + 15:
            target_block = baseline_ciphertext[-32:]  # Last block of baseline ciphertext
        elif num_as < initial_num_as + 31:
            target_block = baseline_ciphertext[-64:-32]  # Second to last block of 32 bytes
        else:
            target_block = baseline_ciphertext[-96:-64]  # Third to last block of 32 bytes

        print(f"Baseline ciphertext last block to match: {target_block} with {num_as} 'a's")

        cycle_count = (num_as - initial_num_as) % block_size
        padding_length = 15 - cycle_count  # Start from 15 and decrement
        if padding_length < 1:
            padding_length += block_size  # Reset to full block padding

        padding_byte_value = 15 - cycle_count  # Start from \x0F and decrement
        if padding_length == 16:
            padding_byte_value = 16  # Reset to \x10

        # Transform match_count to bytes and adjust padding
        matched_bytes = b''.join(match_count)
        padding_length_adjusted = padding_length - len(match_count) + counter
        counter += 1
        if counter > 16:
            counter = 0
        padding = matched_bytes + bytes([padding_byte_value] * padding_length_adjusted)
        print(f"Padding byte value: {padding_byte_value} (Hex {padding_byte_value:02x})")
        print(f"Padding: {padding.hex()} (Length: {padding_length_adjusted})")

        # Inner loop: Try all ASCII characters
        for byte_val in range(0, 256):
            guess_char = bytes([byte_val])  # guess_char as bytes
            print(f"Character '{guess_char.hex()}' (ASCII: '{guess_char.decode('ascii', 'replace')}')")
            trial_input = guess_char + padding
            trial_output = run_command_with_input(process, base64.b64encode(trial_input))
            trial_ciphertext = extract_ciphertext(trial_output)
            print("This is the ciphertext of the inner loop: ", trial_ciphertext)
            trial_block = trial_ciphertext[:32]  # Only compare the first block
            print(f"Now comparing: {trial_block} vs {target_block} for guess '{guess_char}'")

            if trial_block == target_block:
                discovered_secret += chr(byte_val)  # Convert byte to character and add to the secret
                match_count.insert(0, guess_char)  # Add to the beginning of match_count
                print(f"Match found! Character '{guess_char.hex()}' added to secret. Number of matches = {len(match_count)}")
                break

    return discovered_secret, match_count

# Create a single process instance
process = create_challenge_process()

run_initial_command(process)

# Decrypt the secret
secret, count = decrypt_byte_at_a_time(process)
print(f"Decrypted secret: {secret} and {count} with len: ", len(count))


# Make sure to close the process
process.stdin.close()
process.terminate()
process.wait()
