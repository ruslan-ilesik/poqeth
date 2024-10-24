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
h_range = range(63, 64)  # Example range for h
d_range = range(10, 20)   # Example range for d
a_range = range(12, 100)   # Example range for a
k_range = range(14, 60)  # Example range for k
m_value = 32            # Example value for m (you can adjust this as needed)
h_progress = None
# Function to check the condition
def check_condition(h, d, a, k, m):
    #h_progress.write(str((k * a + 7) // 8 + (h - h // d + 7) // 8 + (h // d + 7) // 8))
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
    csv_writer.writerow(['h', 'd', 'a', 'k', 'set_pk_max', 'verify_value'])

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
                        tqdm.write(f"h: {h}, d: {d}, a: {a}, k: {k}")
                        exit()
                        modify_solidity_file(file_path, h, d, a, k, m_value)
                        
                        # Execute the console command
                        command = ["forge", "test", "--gas-report", "--via-ir", "-vvv", "--match-path", "test/sphics2/sphincs_plus.sol"]
                        result = subprocess.run(command, capture_output=True, text=True)

                        output = result.stdout

                        set_pk_max = re.search(r'set_pk\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        verify_value = re.search(r'verify\s+\|\s+(\d+)', output)
                        
                        # Extract values from the command output
                        set_pk_max_value = set_pk_max.group(1) if set_pk_max else 'not found'
                        verify_value_value = verify_value.group(1) if verify_value else 'not found'

                        # Write the result to the CSV file
                        csv_writer.writerow([h, d, a, k, set_pk_max_value, verify_value_value])

                        # Print the result above the progress bars
                        tqdm.write(f"h: {h}, d: {d}, a: {a}, k: {k}\nset_pk: {set_pk_max_value}, verify: {verify_value_value}")
                
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
