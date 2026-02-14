extern int printf(const char *, ...);

volatile int sink;

__attribute__((noipa)) void observe(int v) { sink = v; }

__attribute__((noipa)) int add(int a, int b) {
	observe(a);
	observe(b);
	return a + b;
}

__attribute__((noipa)) int multiply(int a, int b) {
	observe(a);
	observe(b);
	return a * b;
}

__attribute__((noipa)) int subtract(int a, int b) {
	observe(a);
	observe(b);
	return a - b;
}

__attribute__((noipa)) int divide(int a, int b) {
	observe(a);
	observe(b);
	return b ? a / b : 0;
}

int main() {
	int result = add(1, multiply(2, subtract(3, divide(4, 2))));
	printf("%d\n", result);
	return result;
}
