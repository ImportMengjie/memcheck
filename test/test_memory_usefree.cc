#include <iostream>
#include <thread>
#include <chrono>
using namespace std;

void func() {
    uint i = 0;
    while (true) {
        int *a = new (int);
        a[0] = 0;
        delete a;
        if (i == 10) {
            a[0] = i;
        }
        ++i;
        // std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int main() {
    std::thread t1(func);
    t1.join();
}
