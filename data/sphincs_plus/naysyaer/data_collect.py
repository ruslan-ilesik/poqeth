import os
import subprocess
import re
import csv
from tqdm import tqdm

# Get the directory of the current Python script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the path to the Solidity file relative to the script's directory
file_path = os.path.join(script_dir, '../../../test/sphincsPlusNaysayer/sphincsPlusNaysayer.sol')

# Create the directory for storing the CSV file if it doesn't exist
output_dir = os.path.join(script_dir, '')
os.makedirs(output_dir, exist_ok=True)

# Define the path to the CSV file
csv_file_path = os.path.join(output_dir, 'results.csv')

# The range for each parameter
h_range = range(1, 20)  
d_range = range(2, 10)  
a_range = range(1, 64)  
k_range = range(1, 64)  
m_value = 32            

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
    csv_writer.writerow(['h', 'd', 'a', 'k', 'setPk_max', 'naysayerFors','naysayerForsHash','WotsHashNaysayer','wotsNaysayer','xmssNaysayer','setSign'])

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
                        command = ["forge", "test", "--gas-report", "--via-ir", "-vvv", "--match-path", "test/sphincsPlusNaysayer/sphincsPlusNaysayer.sol"]
                        result = subprocess.run(command, capture_output=True, text=True)

                        output = result.stdout

                        setPk_max = re.search(r'setPk\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        naysayerFors = re.search(r'naysayerFors\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        naysayerForsHash = re.search(r'naysayerForsHash\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        WotsHashNaysayer = re.search(r'WotsHashNaysayer\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        wotsNaysayer = re.search(r'wotsNaysayer\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        xmssNaysayer = re.search(r'xmssNaysayer\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        setSign = re.search(r'setSign\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+\d+\s+\|\s+(\d+)', output)
                        
                                                # Extract values from the command output
                        setPk_max_value = setPk_max.group(1) if setPk_max else 'not found'
                        naysayerFors_value = naysayerFors.group(1) if naysayerFors else 'not found'
                        naysayerForsHash_value = naysayerForsHash.group(1) if naysayerForsHash else 'not found'
                        WotsHashNaysayer_value = WotsHashNaysayer.group(1) if WotsHashNaysayer else 'not found'
                        wotsNaysayer_value = wotsNaysayer.group(1) if wotsNaysayer else 'not found'
                        xmssNaysayer_value = xmssNaysayer.group(1) if xmssNaysayer else 'not found'
                        setSign_value = setSign.group(1) if setSign else 'not found'

                        # Write the result to the CSV file
                        csv_writer.writerow([h, d, a, k, setPk_max_value, naysayerFors_value, naysayerForsHash_value, WotsHashNaysayer_value, wotsNaysayer_value, xmssNaysayer_value, setSign_value])

                        # Print the result to the terminal
                        h_progress .write(f"h: {h}, d: {d}, a: {a}, k: {k}")
                        h_progress .write(f"setPk_max: {setPk_max_value}, naysayerFors: {naysayerFors_value}, naysayerForsHash: {naysayerForsHash_value}, WotsHashNaysayer: {WotsHashNaysayer_value}")
                        h_progress .write(f"wotsNaysayer: {wotsNaysayer_value}, xmssNaysayer: {xmssNaysayer_value}, setSign: {setSign_value}")
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
