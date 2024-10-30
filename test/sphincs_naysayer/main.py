import os
import subprocess
import re
import csv
from tqdm import tqdm

# Get the directory of the current Python script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the path to the Solidity file relative to the script's directory
file_path = os.path.join(script_dir, 'sphincs_plus.sol')

# Create the directory for storing the CSV file if it doesn't exist
output_dir = os.path.join(script_dir, 'sphincs_data')
os.makedirs(output_dir, exist_ok=True)

# Define the path to the CSV file
csv_file_path = os.path.join(output_dir, 'results.csv')

# The range for each parameter
h_range = range(1, 20)  # Example range for h
d_range = range(2, 10)   # Example range for d
a_range = range(1, 64)   # Example range for a
k_range = range(1, 64)  # Example range for k
m_value = 32            # Example value for m (you can adjust this as needed)

# Function to check the condition
def check_condition(h, d, a, k, m):
    return (k * a + 7) // 8 + (h - h // d + 7) // 8 + (h // d + 7) // 8 == m

# Function to modify the Solidity file
def modify_solidity_file(file_path, h, d, a, k, m):
    # Read the contents of the file
    with open(file_path, 'r') as file:
        content = file.readlines()

    # Modify the lines with the new values
    for i, line in enumerate(content):
        if re.match(r'\s*uint\s+h\s*=', line):
            content[i] = f'    uint h = {h};\n'
        if re.match(r'\s*uint\s+d\s*=', line):
            content[i] = f'    uint d = {d};\n'
        if re.match(r'\s*uint\s+a\s*=', line):
            content[i] = f'    uint a = {a};\n'
        if re.match(r'\s*uint\s+k\s*=', line):
            content[i] = f'    uint k = {k};\n'
    
    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(content)

# Open the CSV file for writing
with open(csv_file_path, mode='w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    # Write the header row
    csv_writer.writerow(['h', 'd', 'a', 'k', 'set_pk_max', 'naysayer_fors','naysayer_fors_hash','wots_hash_naysayer','wots_naysayer','xmss_naysayer','set_sign'])

    # Set up progress bars
    h_progress = tqdm(total=len(h_range), desc="Processing h", position=0, leave=True)
    d_progress = tqdm(total=len(d_range), desc="Processing d", position=1, leave=True)
    a_progress = tqdm(total=len(a_range), desc="Processing a", position=2, leave=True)
    k_progress = tqdm(total=len(k_range), desc="Processing k", position=3, leave=True)

    # Loop over all possible combinations
    for h in h_range:
        h_progress.set_description(f"Processing h={h}")
        for d in d_range:
            d_progress.set_description(f"Processing d={d}")
            for a in a_range:
                a_progress.set_description(f"Processing a={a}")
                for k in k_range:
                    k_progress.set_description(f"Processing k={k}")
                    if check_condition(h, d, a, k, m_value) and (h - h // d) > 0 and h > d:
                        modify_solidity_file(file_path, h, d, a, k, m_value)
                        
                        # Execute the console command
                        command = ["forge", "test", "--gas-report", "--via-ir", "-vvv", "--match-path", "test/sphincs_naysayer/sphincs_plus.sol"]
                        result = subprocess.run(command, capture_output=True, text=True)

                        output = result.stdout

                        set_pk_max = re.search(r'set_pk\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        naysayer_fors = re.search(r'naysayer_fors\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        naysayer_fors_hash = re.search(r'naysayer_fors_hash\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        wots_hash_naysayer = re.search(r'wots_hash_naysayer\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        wots_naysayer = re.search(r'wots_naysayer\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        xmss_naysayer = re.search(r'xmss_naysayer\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        set_sign = re.search(r'set_sign\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        
                                                # Extract values from the command output
                        set_pk_max_value = set_pk_max.group(1) if set_pk_max else 'not found'
                        naysayer_fors_value = naysayer_fors.group(1) if naysayer_fors else 'not found'
                        naysayer_fors_hash_value = naysayer_fors_hash.group(1) if naysayer_fors_hash else 'not found'
                        wots_hash_naysayer_value = wots_hash_naysayer.group(1) if wots_hash_naysayer else 'not found'
                        wots_naysayer_value = wots_naysayer.group(1) if wots_naysayer else 'not found'
                        xmss_naysayer_value = xmss_naysayer.group(1) if xmss_naysayer else 'not found'
                        set_sign_value = set_sign.group(1) if set_sign else 'not found'

                        # Write the result to the CSV file
                        csv_writer.writerow([h, d, a, k, set_pk_max_value, naysayer_fors_value, naysayer_fors_hash_value, wots_hash_naysayer_value, wots_naysayer_value, xmss_naysayer_value, set_sign_value])

                        # Print the result to the terminal
                        h_progress .write(f"h: {h}, d: {d}, a: {a}, k: {k}")
                        h_progress .write(f"set_pk_max: {set_pk_max_value}, naysayer_fors: {naysayer_fors_value}, naysayer_fors_hash: {naysayer_fors_hash_value}, wots_hash_naysayer: {wots_hash_naysayer_value}")
                        h_progress .write(f"wots_naysayer: {wots_naysayer_value}, xmss_naysayer: {xmss_naysayer_value}, set_sign: {set_sign_value}")
                        h_progress.write("_________________________________________________________")
                
                a_progress.update(1)
                k_progress.n = 0
                k_progress.last_print_n = 0
                k_progress.refresh()

            d_progress.update(1)
            a_progress.n = 0
            a_progress.last_print_n = 0
            a_progress.refresh()

        h_progress.update(1)
        d_progress.n = 0
        d_progress.last_print_n = 0
        d_progress.refresh()

    # Close progress bars
    h_progress.close()
    d_progress.close()
    a_progress.close()
    k_progress.close()
