import re
import os
import subprocess
import csv
from tqdm import tqdm

def replace_values_in_file(file_path, replacements):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    for i in range(len(lines)):
        for pattern, new_value in replacements.items():
            if re.match(pattern, lines[i]):
                lines[i] = re.sub(r'=\s*[^;]+;', f'= {new_value};', lines[i])

    with open(file_path, 'w') as file:
        file.writelines(lines)

def extract_max_values(output):
    set_pk_max = None
    verify_max = None

    # Regular expressions to match the lines
    set_pk_pattern = r'set_pk\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|'
    verify_pattern = r'verify\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|'

    set_pk_match = re.search(set_pk_pattern, output)
    verify_match = re.search(verify_pattern, output)

    if set_pk_match:
        set_pk_max = set_pk_match.group(1)

    if verify_match:
        verify_max = verify_match.group(1)

    return set_pk_max, verify_max

if __name__ == '__main__':
    # Get the current directory of the script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define the file path for xmss.sol
    file_path = os.path.join(current_dir, '../../../test/xmss/xmss.sol')
    for w in tqdm([4,16],desc='param w',leave=False):
        for h in tqdm(range(2,21,2),desc='param h',leave=False):
            with open(os.path.join(current_dir,f'./w_{w}_h_{h}.csv'), 'w', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)
                # Write the header
                csvwriter.writerow(['w','h','i', 'hex_value', 'set_pk', 'verify'])
                for i in tqdm(range(100,157),desc='weight',leave=False):
                    # Create a binary string with i ones followed by (256-i) zeros
                    binary_string = '1' * i + '0' * (256 - i)
                    
                    # Convert the binary string to an integer
                    integer_value = int(binary_string, 2)
                    
                    # Convert the integer to a 32-byte hex string
                    hex_value = f'{integer_value:064x}'

                    # Define the patterns and new values
                    replacements = {
                        r'\s*uint\s+h\s*=': str(h),
                        r'\s*uint\s+w\s*=': str(w),
                        r'\s*bytes32\s+Mp\s*=': '0x'+hex_value
                    }

                    replace_values_in_file(file_path, replacements)
                    
                    # Execute the console command
                    command = ["forge", "test", "--gas-report", "--via-ir", "-vvv", "--match-path", "test/xmss/xmss.sol"]
                    result = subprocess.run(command, capture_output=True, text=True)

                    output = result.stdout

                    set_pk_max, verify_max = extract_max_values(output)

                    # Write the results to the CSV file
                    csvwriter.writerow([w,h,i, hex_value, set_pk_max, verify_max])
        
