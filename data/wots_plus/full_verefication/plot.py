import csv
import matplotlib.pyplot as plt
import os


def read_csv(file_path):
    i_values = []
    verify_values = []

    with open(file_path, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        header = next(csvreader)  # Skip the header row
        for row in csvreader:
            i = int(row[0])
            verify_value = int(row[3])
            i_values.append(i)
            verify_values.append(verify_value)
    return i_values, verify_values

def plot_graphs(i_values_dict, file_name):
    plt.figure(figsize=(12, 6))
    markers = {
        4: "o",
        8: "s",
        16: "d",
        256: "p"
    }
    
    # Plot each dataset with a different color
    for w, (i_values, verify_values) in i_values_dict.items():
        # Use slicing to select every 5th element
        i_values_sliced = i_values[::5]
        verify_values_sliced = [i for i in verify_values[::5]]
        plt.plot(i_values_sliced, verify_values_sliced, marker=markers[w], linestyle='-', label=f'w={w}') # Plot every 5th dot
    
    plt.xlabel('$\\vert\\vert M \\vert\\vert _1$')
    plt.ylabel('Gas')
    plt.yscale("log")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    
    # Save as an image file
    plt.savefig(file_name)

    # Save the plot as file
    plt.savefig(file_name.replace('.png', '.pgf'))  # Replace extension for pgf output
    
    #plt.show()

def main():
    i_values_dict = {}
    script_dir = os.path.dirname(os.path.realpath(__file__))
    
    # Read the data for each value of w
    for w in [4, 8, 16, 256]:
        file_path = os.path.join(script_dir, f'{w}.csv')
        i_values, verify_values = read_csv(file_path)
        i_values_dict[w] = (i_values, verify_values)
    
    # Plot the graphs on the same plot and save TikZ output
    plot_graphs(i_values_dict, 'wots_full_plot.png')

if __name__ == "__main__":
    main()
