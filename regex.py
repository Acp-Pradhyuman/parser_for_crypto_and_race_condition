import os
import re

def remove_comments_and_strings(line):
    # Remove single-line comments
    line = re.sub(r'//.*', '', line)
    # Remove multi-line comments
    line = re.sub(r'/\*.*?\*/', '', line, flags=re.DOTALL)
    # Remove string literals
    line = re.sub(r'"([^"\\]*(\\.[^"\\]*)*)"', '', line)
    return line.strip()

def find_insecure_crypto(directory):
    # List of weak functions
    weak_funcs = [
        "MD5", "SHA1", "EVP_md5", "EVP_sha1",
        "DES_ecb_encrypt"
    ]
    # Create a regex pattern to match the weak functions
    insecure_pattern = re.compile(r'\b(' + '|'.join(weak_funcs) + r')\b', re.IGNORECASE)

    vulnerabilities = []

    # Walk through the directory
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.cpp'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line_number, line in enumerate(f, start=1):
                        cleaned_line = remove_comments_and_strings(line)

                        # Search for insecure cryptographic methods in the cleaned line
                        if cleaned_line and insecure_pattern.search(cleaned_line):
                            function_name = insecure_pattern.search(cleaned_line).group(0)  # Get the matched function
                            vulnerability_info = {
                                "file": file_path,
                                "line": line_number,
                                "function": function_name,
                                "explanation": (
                                    f"{function_name} is an insecure cryptographic function. "
                                    "These functions are considered weak due to vulnerabilities "
                                    "that allow for collision attacks, where two different inputs "
                                    "produce the same hash. This can lead to security issues such as "
                                    "forgery of digital signatures and data integrity violations."
                                ),
                                "suggestion": (
                                    "Consider using stronger hashing algorithms like SHA-256 or SHA-3. "
                                    "Additionally, review the cryptographic standards for your application "
                                    "to ensure compliance with modern security practices."
                                )
                            }
                            vulnerabilities.append(vulnerability_info)

    return vulnerabilities

directory_to_scan = r'D:\Desktop\mtech\sem-1\cns\parser\src'
results = find_insecure_crypto(directory_to_scan)

if results:
    for result in results:
        print(f"File: {result['file']}")
        print(f"Line: {result['line']}")
        print(f"Function: {result['function']}")
        print(f"Explanation: {result['explanation']}")
        print(f"Suggestion: {result['suggestion']}")
        print("-" * 80)  # Separator for better readability
else:
    print("No vulnerabilities found.")