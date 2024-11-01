#include <iostream>

int divide_numbers(int numerator, int denominator) {
    return numerator / denominator; // This will throw an exception if denominator is 0
}

int main() {
    std::cout << "10 / 2 = " << divide_numbers(10, 2) << std::endl;
    std::cout << "10 / 0 = " << divide_numbers(10, 0) << std::endl; // This will cause a crash
    return 0; // Successful execution, but it may not reach here
}