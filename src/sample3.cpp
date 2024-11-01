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

void sha256_hash_function() {
    const char* input = "data";
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_length;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        std::cerr << "Error creating SHA-256 context" << std::endl;
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, &output_length) != 1) {
        std::cerr << "Error computing SHA-256" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    std::cout << "SHA-256: ";
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

    // Call the SHA-256 function
    sha256_hash_function();

    return 0;
}