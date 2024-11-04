import pathlib, os, subprocess, re, csv, tqdm


def replace_hex_value_in_file(file_path, new_hex_value):
    # Ensure the new_hex_value is a valid hex string without "0x" prefix
    if new_hex_value.startswith("0x"):
        new_hex_value = new_hex_value[2:]

    # Read the file content
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Modify the specific line
    for i in range(len(lines)):
        if 'bytes32 hashed_message = hex"' in lines[i]:
            start_index = lines[i].index('hex"') + 4
            end_index = lines[i].index('";', start_index)
            lines[i] = lines[i][:start_index] + new_hex_value + lines[i][end_index:]
            break

    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(lines)


def replace_w_value_in_file(file_path, new_w_value):
    # Read the file content
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Modify the specific line
    for i in range(len(lines)):
        if 'uint16 w = ' in lines[i]:
            start_index = lines[i].index('uint16 w = ') + len('uint16 w = ')
            end_index = lines[i].index(';', start_index)
            lines[i] = lines[i][:start_index] + str(new_w_value) + lines[i][end_index:]
            break

    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(lines)


FILE_PATH = os.path.dirname(os.path.abspath(__file__))+"/../../../test/wots_naysayer/wots_naysayer.sol"

for w in tqdm.tqdm([4,8,16,256]):
    replace_w_value_in_file(FILE_PATH, w)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f'{w}.csv'), 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        # Write the header
        csvwriter.writerow(['i', 'hex_value', 'setPk_max', 'verify_value'])

        for i in tqdm.tqdm(range(256),leave=False):
            # Create a binary string with i ones followed by (256-i) zeros
            binary_string = '1' * i + '0' * (256 - i)
            
            # Convert the binary string to an integer
            integer_value = int(binary_string, 2)
            
            # Convert the integer to a 32-byte hex string
            hex_value = f'{integer_value:064x}'
            
            replace_hex_value_in_file(FILE_PATH, hex_value)
            

            # Execute the console command
            command = ["forge", "test", "--gas-report", "--via-ir", "-vvv", "--match-path", "test/wots_naysayer/wots_naysayer.sol"]
            result = subprocess.run(command, capture_output=True, text=True)

            output = result.stdout
            setPk_max = re.search(r'setPk\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
            verify_value = re.search(r'naysayer\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
            
            # Extract and print the command output
            setPk_max_value = setPk_max.group(1) if setPk_max else 'not found'
            verify_value_value = verify_value.group(1) if verify_value else 'not found'
            
            # Write the results to the CSV file
            csvwriter.writerow([i, hex_value, setPk_max_value, verify_value_value])

