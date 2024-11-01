import os
import subprocess

# Set your GCC directory and OpenSSL paths
gcc_dir = r"C:\gcc-14.1.0\bin"  # Adjust this to your GCC installation
os.environ["PATH"] += os.pathsep + gcc_dir

# Specify paths for OpenSSL
openssl_include = r"C:\Program Files\OpenSSL-Win64\include"  # Adjust as necessary
openssl_lib = r"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD"  # Adjust as necessary

# Directory and name for the C++ file
cpp_file_path = r'D:\Desktop\mtech\sem-1\cns\parser\src\openssl_test.cpp'  # Adjust path as needed

# C++ code that initializes OpenSSL
cpp_code = f'''#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    std::cout << "OpenSSL initialized successfully." << std::endl;
    return 0;
}}
'''

# Write the C++ code to a file
with open(cpp_file_path, 'w') as cpp_file:
    cpp_file.write(cpp_code)

# Get the base name for the output executable
base_name = os.path.splitext(os.path.basename(cpp_file_path))[0]

# Compile the C++ file with OpenSSL libraries
compile_command = (
    f'g++ -g "{cpp_file_path}" -o "{base_name}" '
    f'-I"{openssl_include}" "{openssl_lib}\\libssl.lib" "{openssl_lib}\\libcrypto.lib" -pthread'
)

print(f"\nCompiling {cpp_file_path}...")
print(f"Compile command: {compile_command}")

compile_status = os.system(compile_command)

if compile_status != 0:
    print(f"Compilation failed for {cpp_file_path}. Exit code: {compile_status}")
else:
    print(f"Running {base_name}...")

    # Run the compiled program
    try:
        program_output = subprocess.check_output(
            [f'./{base_name}'],
            stderr=subprocess.STDOUT,
            text=True
        )
        print("Program output:")
        print(program_output)
    except subprocess.CalledProcessError as e:
        print(f"Program encountered an error:\n{e.output}")
        print(f"Exit code: {e.returncode}")

    print(f"Finished processing {base_name}.")