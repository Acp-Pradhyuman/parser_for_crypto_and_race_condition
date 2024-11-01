#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <openssl/evp.h>
#include <cstring> // for strlen

int shared_data_safe = 0;     // Safe version
std::mutex mtx;               // Mutex for safe access

void increment_shared_data_safe() {
    for (int i = 0; i < 100000; ++i) {
        std::lock_guard<std::mutex> guard(mtx); // Lock the mutex
        shared_data_safe++;  // Safe increment with mutex protection
    }
}

void hash1() {
    const char* input = "data";
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_length;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Error creating hash1 context" << std::endl;
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, &output_length) != 1) {
        std::cerr << "Error computing hash1" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    std::cout << "Hash-1: ";
    for (unsigned int i = 0; i < output_length; i++) {
        printf("%02x", output[i]);
    }
    std::cout << std::endl;
}

void hash2() {
    const char* input = "data";
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_length;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Error creating hash2 context" << std::endl;
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha1(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, &output_length) != 1) {
        std::cerr << "Error computing hash2" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    std::cout << "Hash-2: ";
    for (unsigned int i = 0; i < output_length; i++) {
        printf("%02x", output[i]);
    }
    std::cout << std::endl;
}

int main() {
    const int num_threads = 3;  // Reduced number of threads for clarity
    std::vector<std::thread> threads;

    // Start multiple threads that modify shared_data_safe
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(increment_shared_data_safe);
    }

    // Join all threads for safe increment
    for (auto& t : threads) {
        t.join();
    }

    std::cout << "Final shared_data (safe): " << shared_data_safe << std::endl;

    // Call the hash functions
    hash1();
    hash2();

    return 0;
}