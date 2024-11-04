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
    setPk_max = None
    verify_max = None
    verify_max2 = None
    verify_max3 = None

    # Regular expressions to match the lines
    setPk_pattern = r'setPk\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|'
    verify_pattern = r'naysayerHT\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|'
    verify_pattern2 = r'naysayerLtree\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|'
    verify_pattern3 = r'naysayerWots\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|'

    setPk_match = re.search(setPk_pattern, output)
    verify_match = re.search(verify_pattern, output)
    verify_match2 = re.search(verify_pattern2, output)
    verify_match3 = re.search(verify_pattern3, output)

    if setPk_match:
        setPk_max = setPk_match.group(1)

    if verify_match:
        verify_max = verify_match.group(1)
    
    
    if verify_match2:
        verify_max2 = verify_match2.group(1)

    if verify_match3:
        verify_max3 = verify_match3.group(1)


    return setPk_max, verify_max, verify_max2, verify_max3

if __name__ == '__main__':
    # Get the current directory of the script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define the file path for xmss.sol
    file_path = os.path.join(current_dir, '../../../test/xmssNaysayer/xmssNaysayer.sol')
    global_loop = tqdm([4,16],desc='param w',leave=False)
    for w in global_loop:
        for h in tqdm(range(2,21,2),desc='param h',leave=False):
            with open(os.path.join(current_dir,f'./w_{w}_h_{h}.csv'), 'w', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)
                # Write the header
                csvwriter.writerow(['w','h','i', 'hex_value', 'setPk', 'naysayerHT','naysayerLtree','naysayerWots'])
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
                    command = ["forge", "test", "--gas-report", "--via-ir", "-vvv", "--match-path", "test/xmssNaysayer/xmssNaysayer.sol"]
                    result = subprocess.run(command, capture_output=True, text=True)

                    output = result.stdout

                    setPk_max, verify_max,verify_max2,verify_max3 = extract_max_values(output)

                    # Write the results to the CSV file
                    csvwriter.writerow([w,h,i, hex_value, setPk_max, verify_max,verify_max2,verify_max3])
                    global_loop.write(str([w,h,i, hex_value, setPk_max, verify_max,verify_max2,verify_max3]))
        
