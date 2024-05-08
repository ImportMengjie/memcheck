#include <iostream>
using namespace std;

int main(){
    int *a = new(int);
    a[2] = 10;
    delete a;
}
