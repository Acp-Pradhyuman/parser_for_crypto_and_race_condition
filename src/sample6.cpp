#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/des.h> // Include DES header
#include <cstring> // for strlen
#include <chrono>
#include <cstdlib>

int shared_data_unsafe = 0;  // Unsafe version
int shared_data_safe = 0;     // Safe version
std::mutex mtx;               // Mutex for safe access

void increment_shared_data_unsafe() {
    for (int i = 0; i < 100000; ++i) {
        shared_data_unsafe++;  // Unsafe increment
    }
}

void increment_shared_data_safe() {
    for (int i = 0; i < 100000; ++i) {
        std::lock_guard<std::mutex> guard(mtx); // Lock the mutex
        shared_data_safe++;  // Safe increment with mutex protection
    }
}

void md5_hash_function() {
    const char* input = "data";
    unsigned char output[MD5_DIGEST_LENGTH];

    MD5((unsigned char*)input, strlen(input), output); // Deprecated call

    std::cout << "MD5 (deprecated): ";
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", output[i]);
    }
    std::cout << std::endl;
}

void sha1_hash_function() {
    const char* input = "data";
    unsigned char output[SHA_DIGEST_LENGTH];

    SHA1((unsigned char*)input, strlen(input), output); // Deprecated call

    std::cout << "SHA-1 (deprecated): ";
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", output[i]);
    }
    std::cout << std::endl;
}

void md5_hash_function_evp() {
    const char* input = "data";
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_length;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Error creating MD5 context" << std::endl;
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, &output_length) != 1) {
        std::cerr << "Error computing MD5" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    std::cout << "MD5 (EVP): ";
    for (unsigned int i = 0; i < output_length; i++) {
        printf("%02x", output[i]);
    }
    std::cout << std::endl;
}

void sha1_hash_function_evp() {
    const char* input = "data";
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_length;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Error creating SHA-1 context" << std::endl;
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha1(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, &output_length) != 1) {
        std::cerr << "Error computing SHA-1" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    std::cout << "SHA-1 (EVP): ";
    for (unsigned int i = 0; i < output_length; i++) {
        printf("%02x", output[i]);
    }
    std::cout << std::endl;
}

// DES encryption function
void des_encrypt(const std::string& input, const std::string& key) {
    DES_cblock key_schedule;
    DES_key_schedule schedule;

    // Set the key
    memcpy(key_schedule, key.c_str(), 8);
    DES_set_key_checked(&key_schedule, &schedule);

    // Prepare buffers
    std::string output((input.size() + 7) / 8 * 8, '\0');
    DES_cblock input_block;
    DES_cblock output_block;

    // Encrypt in blocks of 8 bytes
    for (size_t i = 0; i < input.size(); i += 8) {
        memcpy(input_block, input.c_str() + i, 8);
        DES_ecb_encrypt(&input_block, &output_block, &schedule, DES_ENCRYPT);
        memcpy(&output[i], output_block, 8);
    }

    std::cout << "Encrypted (DES): ";
    for (char c : output) {
        printf("%02x", static_cast<unsigned char>(c));
    }
    std::cout << std::endl;
}

// DES decryption function
void des_decrypt(const std::string& input, const std::string& key) {
    DES_cblock key_schedule;
    DES_key_schedule schedule;

    // Set the key
    memcpy(key_schedule, key.c_str(), 8);
    DES_set_key_checked(&key_schedule, &schedule);

    // Prepare buffers
    std::string output((input.size() + 7) / 8 * 8, '\0');
    DES_cblock input_block;
    DES_cblock output_block;

    // Decrypt in blocks of 8 bytes
    for (size_t i = 0; i < input.size(); i += 8) {
        memcpy(input_block, input.c_str() + i, 8);
        DES_ecb_encrypt(&input_block, &output_block, &schedule, DES_DECRYPT);
        memcpy(&output[i], output_block, 8);
    }

    std::cout << "Decrypted (DES): " << output << std::endl;
}

int main() {
    const int num_threads = 3;  // Reduced number of threads for clarity
    std::vector<std::thread> threads;

    // Start multiple threads that modify shared_data_unsafe
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(increment_shared_data_unsafe);
    }

    // Join all threads for unsafe increment
    for (auto& t : threads) {
        t.join();
    }

    std::cout << "Final shared_data (unsafe): " << shared_data_unsafe << std::endl;

    // Clear the thread vector for the next use
    threads.clear();

    // Start multiple threads that modify shared_data_safe
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(increment_shared_data_safe);
    }

    // Join all threads for safe increment
    for (auto& t : threads) {
        t.join();
    }

    std::cout << "Final shared_data (safe): " << shared_data_safe << std::endl;

    md5_hash_function();
    sha1_hash_function();
    md5_hash_function_evp();
    sha1_hash_function_evp();

    // DES encryption and decryption example
    std::string key = "12345678"; // Example key (must be 8 bytes for DES)
    std::string plaintext = "Hello, DES!";

    // Pad plaintext to be a multiple of 8 bytes
    while (plaintext.size() % 8 != 0) {
        plaintext += '\0'; // Simple null padding
    }

    des_encrypt(plaintext, key);
    des_decrypt(plaintext, key);

    return 0;
}