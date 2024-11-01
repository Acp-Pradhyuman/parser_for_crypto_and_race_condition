import clang.cindex
import os
import re

class CppVulnerabilityAnalyzer:
    def __init__(self, directory):
        self.directory = directory
        self.index = clang.cindex.Index.create()
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
        self.dynamic_patterns = [
            r'\b(md5|sha1|des)\b',
            r'\b(digest|hash|encrypt|generate)\b.*\b(init|update|final|ecb)\b',
            r'\b(use|apply|create|compute)\b.*\b(md5|sha1|des)\b'
        ]

    def analyze(self):
        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith('.cpp'):
                    file_path = os.path.join(root, file)
                    translation_unit = self.index.parse(file_path)
                    self.traverse_ast(translation_unit.cursor, file_path)

    def traverse_ast(self, node, file_path):
        try:
            self.detect_weak_crypto(node, file_path)
        except ValueError as e:
            print(f"Skipping node due to error: {e}")

        for child in node.get_children():
            self.traverse_ast(child, file_path)

    def detect_weak_crypto(self, node, file_path):
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            if any(weak_func in node.spelling for weak_func in self.weak_funcs):
                header_info = self.get_header_info(node.spelling)
                self.report_vulnerability(node, file_path, header_info)

        for child in node.get_children():
            try:
                if child.kind == clang.cindex.CursorKind.STRING_LITERAL:
                    if any(re.search(pattern, child.spelling, re.IGNORECASE) for pattern in self.dynamic_patterns):
                        self.report_string_literal_vulnerability(child, file_path)

                if any(weak_func in child.spelling for weak_func in self.weak_funcs):
                    header_info = self.get_header_info(child.spelling)
                    self.report_vulnerability(child, file_path, header_info)

                for pattern in self.dynamic_patterns:
                    if re.search(pattern, child.spelling, re.IGNORECASE):
                        header_info = self.get_header_info(child.spelling)
                        self.report_vulnerability(child, file_path, header_info)

            except ValueError as e:
                print(f"Skipping child node due to error: {e}")

    def report_string_literal_vulnerability(self, node, file_path):
        line_number = node.location.line
        line_content = self.get_line_content(file_path, line_number)

        vulnerability_info = {
            "file": file_path,
            "line_number": line_number,
            "line": line_content,
            "function": "String Literal",
            "header": "N/A",
            "explanation": (
                "This string literal suggests a potential use of a weak cryptographic function. "
                "Review the context of this string for security concerns."
            ),
            "suggestion": (
                "Consider reviewing the string content for potential security issues related to "
                "weak cryptographic algorithms."
            )
        }
        self.vulnerabilities.append(vulnerability_info)

    def get_header_info(self, function_name):
        return self.weak_headers.get(function_name, "Unknown header")

    def report_vulnerability(self, node, file_path, header_info):
        line_number = node.location.line
        line_content = self.get_line_content(file_path, line_number)

        vulnerability_info = {
            "file": file_path,
            "line_number": line_number,
            "line": line_content,
            "function": node.spelling,
            "header": header_info,
            "explanation": (
                f"{node.spelling} is an insecure cryptographic function. "
                "Both MD5 and SHA-1 are considered weak due to vulnerabilities "
                "that allow for collision attacks."
            ),
            "suggestion": (
                "Consider using stronger hashing algorithms like SHA-256 or SHA-3, "
                "or more secure encryption methods such as AES."
            )
        }
        self.vulnerabilities.append(vulnerability_info)

    def get_line_content(self, file_path, line_number):
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            return lines[line_number - 1].strip() if 0 < line_number <= len(lines) else ""

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
    clang.cindex.Config.set_library_file(
        r'C:\Program Files\LLVM\bin\libclang.dll')
    analyzer = CppVulnerabilityAnalyzer(directory_to_scan)
    analyzer.analyze()
    analyzer.report()