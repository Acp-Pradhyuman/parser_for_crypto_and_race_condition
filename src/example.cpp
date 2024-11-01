#include <iostream>
#include <stdexcept> // For std::runtime_error
#include <cstdlib>   // For EXIT_FAILURE

int divide_numbers(int numerator, int denominator) {
    if (denominator == 0) {
        throw std::runtime_error("Cannot divide by zero!");
    }
    return numerator / denominator;
}

int main() {
    try {
        std::cout << "10 / 2 = " << divide_numbers(10, 2) << std::endl;
        std::cout << "10 / 0 = " << divide_numbers(10, 0) << std::endl; // This will throw an exception
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl; // Handle the specific exception
        return EXIT_FAILURE; // Exit with failure status
    } catch (...) {
        std::cerr << "An unknown error occurred!" << std::endl;
        return EXIT_FAILURE; // Exit with failure status
    }

    return 0; // Successful execution
}