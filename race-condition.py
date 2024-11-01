import glob
import os
import subprocess

# Add custom GCC directory to PATH
gcc_dir = r"C:\mingw64\bin"
os.environ["PATH"] += os.pathsep + gcc_dir

# Add OpenSSL DLL directory to PATH
openssl_dll_dir = r"C:\Program Files\OpenSSL-Win64"  # Adjust as necessary
os.environ["PATH"] += os.pathsep + openssl_dll_dir

# Check for required DLLs
required_dlls = [
    r"C:\Program Files\OpenSSL-Win64\libcrypto-3-x64.dll",
    r"C:\Program Files\OpenSSL-Win64\libssl-3-x64.dll"
]

for dll in required_dlls:
    if not os.path.exists(dll):
        print(f"Warning: {dll} not found!")
    else:
        print(f"Found: {dll}")

# Directory containing your .cpp files
cpp_dir = r'D:\Desktop\mtech\sem-1\cns\parser\src\*.cpp'

# Path to OpenSSL installation
openssl_include = r'C:\Program Files\OpenSSL-Win64\include'
openssl_lib = r'C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD'

# Compile and run each .cpp file
for cpp_file_path in glob.glob(cpp_dir):
    base_name = os.path.splitext(os.path.basename(cpp_file_path))[0]
    
    print(f"\nCompiling {cpp_file_path}...")

    # Compile the C++ file
    compile_command = (
        f'g++ -g "{cpp_file_path}" -o "{base_name}" '
        f'-I"{openssl_include}" "{openssl_lib}\\libssl.lib" "{openssl_lib}\\libcrypto.lib" -pthread'
    )
    print(f"Compile command: {compile_command}")  # Debugging line
    
    compile_status = os.system(compile_command)
    
    if compile_status != 0:
        print(f"Compilation failed for {cpp_file_path}.")
        continue
    
    print(f"Running Valgrind on {base_name}...")

    # Run Valgrind and capture output (assuming Valgrind is available)
    try:
        valgrind_output = subprocess.check_output(
            ['valgrind', '--tool=helgrind', '--trace-children=yes', f'./{base_name}'],
            stderr=subprocess.STDOUT,
            text=True  # Capture output as string
        )
        print("Valgrind output:")
        print(valgrind_output)
    except subprocess.CalledProcessError as e:
        print(f"Valgrind encountered an error:\n{e.output}")

    print(f"Finished processing {base_name}.")