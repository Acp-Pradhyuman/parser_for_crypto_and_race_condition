#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    std::cout << "OpenSSL initialized successfully." << std::endl;
    return 0;
}
