import glob
import os
import subprocess

# Directory containing your .cpp files
cpp_dir = '/mnt/d/Desktop/mtech/sem-1/cns/parser/src/*.cpp'  # Adjust as necessary

# Compile and run each .cpp file
for cpp_file_path in glob.glob(cpp_dir):
    # Get the base name without extension for the output file
    base_name = os.path.splitext(os.path.basename(cpp_file_path))[0]

    print(f"\nCompiling {cpp_file_path}...")

    # Compile the C++ file
    compile_command = f'g++ -g "{cpp_file_path}" -o "{base_name}" -lssl -lcrypto -pthread'
    compile_status = os.system(compile_command)

    if compile_status != 0:
        print(f"Compilation failed for {cpp_file_path}.")
        continue

    print(f"Running {base_name}...")

    # Run the compiled program
    try:
        program_output = subprocess.check_output(
            [f'./{base_name}'],
            stderr=subprocess.STDOUT,
            text=False  # Capture output as bytes
        )
        print("Program output:")
        print(program_output.decode(errors='replace'))  # Decode with error handling
    except subprocess.CalledProcessError as e:
        print(f"Program encountered an error:\n{e.output.decode(errors='replace')}")

    print(f"Running Valgrind on {base_name}...")

    # Run Valgrind and capture output
    try:
        valgrind_output = subprocess.check_output(
            ['valgrind', '--tool=helgrind', '--trace-children=yes', f'./{base_name}'],
            stderr=subprocess.STDOUT,
            text=False  # Capture output as bytes
        )
        print("Valgrind output:")
        print(valgrind_output.decode(errors='replace'))  # Decode with error handling
    except subprocess.CalledProcessError as e:
        print(f"Valgrind encountered an error:\n{e.output.decode(errors='replace')}")

    # Delete the generated executable
    try:
        os.remove(base_name)
        print(f"Deleted executable {base_name}.")
    except OSError as e:
        print(f"Error deleting file {base_name}: {e}")

    print(f"Finished processing {base_name}.")