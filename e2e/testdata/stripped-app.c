/* stripped-app.c - plain C without anti-inlining attributes.
 *
 * Used by the e2e test suite to exercise DetectFunctionsFromELF on a
 * realistic optimized binary where GCC is free to inline and apply
 * tail-call optimisation. Under -O2 several of these functions are
 * inlined or have their recursion converted to loops, reducing the
 * prologue and call-site signal available to the detector.
 */
#include <stdio.h>

int add(int a, int b) { return a + b; }
int mul(int a, int b) { return a * b; }
int factorial(int n) { return n <= 1 ? 1 : n * factorial(n - 1); }
int fib(int n) { if (n <= 1) return n; return fib(n - 1) + fib(n - 2); }
int main(void) { printf("%d %d\n", factorial(5), fib(7)); return 0; }
