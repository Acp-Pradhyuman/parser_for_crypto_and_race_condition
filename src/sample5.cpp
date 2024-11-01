#include <iostream>
#include <thread>
#include <mutex>

int counter = 0; // Shared variable
std::mutex mtx; // Mutex for synchronization

void increment() {
    for (int i = 0; i < 100000; ++i) {
        mtx.lock(); // Lock the mutex before accessing the shared variable
        counter++; // Increment the shared variable
        mtx.unlock(); // Unlock the mutex after the operation
    }
}

int main() {
    std::thread t1(increment);
    std::thread t2(increment);

    t1.join();
    t2.join();

    std::cout << "Final counter value: " << counter << std::endl; // Expect 200000
    return 0;
}