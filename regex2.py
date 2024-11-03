import os
import re

class CppVulnerabilityAnalyzer:
    def __init__(self, directory):
        self.directory = directory
        self.vulnerabilities = []
        self.weak_funcs = [
            "MD5", "SHA1", "EVP_md5", "EVP_sha1",
            "DES_ecb_encrypt", "SHA1_Init", "SHA1_Update",
            "SHA1_Final", "SHA1_Transform", "PKCS5_PBKDF2_HMAC_SHA1",
            "EVP_md5_sha1", "MD5_CTX", "MD5state_st",
            "MD5_Init", "MD5_Update", "MD5_Final", "MD5_Transform"
        ]
        self.weak_headers = {
            "MD5": "<openssl/md5.h>",
            "SHA1": "<openssl/sha.h>",
            "EVP_md5": "<openssl/evp.h>",
            "EVP_sha1": "<openssl/evp.h>",
            "DES_ecb_encrypt": "<openssl/des.h>",
            "SHA1_Init": "<openssl/sha.h>",
            "SHA1_Update": "<openssl/sha.h>",
            "SHA1_Final": "<openssl/sha.h>",
            "SHA1_Transform": "<openssl/sha.h>",
            "PKCS5_PBKDF2_HMAC_SHA1": "<openssl/evp.h>",
            "EVP_md5_sha1": "<openssl/evp.h>",
            "MD5_CTX": "<openssl/md5.h>",
            "MD5state_st": "<openssl/md5.h>",
            "MD5_Init": "<openssl/md5.h>",
            "MD5_Update": "<openssl/md5.h>",
            "MD5_Final": "<openssl/md5.h>",
            "MD5_Transform": "<openssl/md5.h>"
        }

    def analyze(self):
        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith('.cpp'):
                    file_path = os.path.join(root, file)
                    self.scan_file(file_path)

    def scan_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, start=1):
                self.check_for_weak_funcs(line, line_number, file_path)

    def check_for_weak_funcs(self, line, line_number, file_path):
        for weak_func in self.weak_funcs:
            # Using regex to match function calls
            pattern = rf'\b{weak_func}\s*\('
            if re.search(pattern, line):
                header_info = self.get_header_info(weak_func)
                self.report_vulnerability(weak_func, line_number, file_path, header_info, line.strip())

    def report_vulnerability(self, function_name, line_number, file_path, header_info, line_content):
        vulnerability_info = {
            "file": file_path,
            "line_number": line_number,
            "line": line_content,
            "function": function_name,
            "header": header_info,
            "explanation": (
                f"{function_name} is an insecure cryptographic function. "
                "Both MD5 and SHA-1 are considered weak due to vulnerabilities "
                "that allow for collision attacks."
            ),
            "suggestion": (
                "Consider using stronger hashing algorithms like SHA-256 or SHA-3, "
                "or more secure encryption methods such as AES."
            )
        }
        self.vulnerabilities.append(vulnerability_info)

    def get_header_info(self, function_name):
        return self.weak_headers.get(function_name, "Unknown header")

    def report(self):
        if self.vulnerabilities:
            for result in self.vulnerabilities:
                print(f"File: {result['file']}")
                print(f"Line Number: {result['line_number']}")
                print(f"Line: {result['line']}")
                print(f"Function: {result['function']}")
                print(f"Header: {result['header']}")
                print(f"Explanation: {result['explanation']}")
                print(f"Suggestion: {result['suggestion']}")
                print("-" * 80)
        else:
            print("\nNo vulnerabilities detected.")

if __name__ == "__main__":
    directory_to_scan = r'D:\Desktop\mtech\sem-1\cns\parser\src'
    analyzer = CppVulnerabilityAnalyzer(directory_to_scan)
    analyzer.analyze()
    analyzer.report()