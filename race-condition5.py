import glob
import os
import subprocess
import uuid  # To generate unique names for executables
from concurrent.futures import ProcessPoolExecutor  # Use processes for CPU-bound tasks
from pathlib import Path

# Directory containing your .cpp files
cpp_dir = '/mnt/d/Desktop/mtech/sem-1/cns/parser/src/*.cpp'

def compile_and_run(cpp_file_path):
    try:
        # Get the base name without extension for the output file
        base_name = os.path.splitext(os.path.basename(cpp_file_path))[0]
        base_path = os.path.dirname(cpp_file_path)

        # Create a unique executable name (to avoid name collisions)
        unique_id = str(uuid.uuid4().hex[:8])  # Create a short unique identifier
        executable_name = f"{base_name}_{unique_id}"  # Unique binary name

        print(f"Compiling {cpp_file_path}...")

        # Compile the C++ file
        compile_command = f'g++ -g "{cpp_file_path}" -o "{executable_name}" -lssl -lcrypto -pthread'
        compile_status = subprocess.run(compile_command, shell=True, cwd=base_path)
        
        if compile_status.returncode != 0:
            print(f"Compilation failed for {cpp_file_path}.")
            return
        
        print(f"Running {executable_name}...")

        # Run the compiled program
        try:
            program_output = subprocess.check_output(
                [f'./{executable_name}'],
                stderr=subprocess.STDOUT,
                text=True,  # Capture output as text (string)
                cwd=base_path
            )
            print(f"Program output:\n{program_output}")
        except subprocess.CalledProcessError as e:
            print(f"Program encountered an error:\n{e.output}")
        
        print(f"Running Valgrind on {executable_name}...")

        # Run Valgrind and capture output
        try:
            valgrind_output = subprocess.check_output(
                ['valgrind', '--tool=helgrind', '--trace-children=yes', f'./{executable_name}'],
                stderr=subprocess.STDOUT,
                text=True,  # Capture output as text (string)
                cwd=base_path
            )
            print(f"Valgrind output:\n{valgrind_output}")
        except subprocess.CalledProcessError as e:
            print(f"Valgrind encountered an error:\n{e.output}")

        # Check if the executable exists before trying to delete
        executable_path = os.path.join(base_path, executable_name)
        if os.path.exists(executable_path):
            try:
                os.remove(executable_path)
                print(f"Deleted executable {executable_name}.")
            except OSError as e:
                print(f"Error deleting file {executable_name}: {e}")
        else:
            print(f"Executable {executable_name} does not exist, skipping deletion.")

        print(f"Finished processing {executable_name}.")
    except Exception as e:
        print(f"Unexpected error processing {cpp_file_path}: {str(e)}")

def analyze_cpp_files():
    # Use ProcessPoolExecutor to parallelize the tasks (instead of ThreadPoolExecutor)
    with ProcessPoolExecutor(max_workers=4) as executor:  # Adjust workers based on your CPU
        futures = []
        for cpp_file_path in glob.glob(cpp_dir):
            futures.append(executor.submit(compile_and_run, cpp_file_path))
        
        # Wait for all tasks to complete
        for future in futures:
            future.result()  # This ensures that any exceptions raised are propagated

if __name__ == "__main__":
    analyze_cpp_files()