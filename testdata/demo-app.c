__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int multiply(int a, int b) { return a * b; }
__attribute__((noinline)) int subtract(int a, int b) { return a - b; }
__attribute__((noinline)) int divide(int a, int b) { return b ? a / b : 0; }
int main() { return add(1, multiply(2, subtract(3, divide(4, 2)))); }
