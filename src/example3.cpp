#include <iostream>
#include <string>

int divide_numbers(int numerator, int denominator) {
    return numerator / denominator; // This will throw an exception if denominator is 0
}

int convert_to_int(const std::string& str) {
    return std::stoi(str); // This can throw std::invalid_argument if the conversion fails
}

int main() {
    std::cout << "10 / 2 = " << divide_numbers(10, 2) << std::endl;
    std::cout << "10 / 0 = " << divide_numbers(10, 0) << std::endl; // Division by zero
    std::cout << "Converting 'abc' to int = " << convert_to_int("abc") << std::endl; // Invalid conversion
    return 0; // Successful execution, but it may not reach here
}